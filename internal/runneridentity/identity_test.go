package runneridentity_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/runneridentity"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

var subjectAlternativeNameOID = asn1.ObjectIdentifier{2, 5, 29, 17}
var authorityKeyIdentifierOID = asn1.ObjectIdentifier{2, 5, 29, 35}

func TestIdentityAndEvidenceCannotBeForgedOrSerializedAsWireObjects(t *testing.T) {
	var identity runneridentity.Identity
	var evidence runneridentity.Evidence
	if identity.Valid() || evidence.Valid() {
		t.Fatal("zero Identity or Evidence was valid")
	}
	for name, target := range map[string]any{"identity": &identity, "evidence": &evidence} {
		if err := json.Unmarshal([]byte(`{}`), target); err == nil {
			t.Fatalf("json.Unmarshal(%s) error = nil; want wire construction rejection", name)
		}
	}
	for name, value := range map[string]any{"identity": identity, "evidence": evidence} {
		if encoded, err := json.Marshal(value); err == nil {
			t.Fatalf("json.Marshal(%s) = %s, nil; want rejection", name, encoded)
		}
		if rendered := fmt.Sprintf("%+v", value); rendered == "" || rendered == "{}" {
			t.Fatalf("fmt.Sprintf(%s) = %q; want explicit redaction", name, rendered)
		}
	}
}

func TestIdentityRequiresExactlyOneURIAndNoOtherSANForms(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	validURI := mustURL(t, "spiffe://aiops.example/runner/read/read-runner-01")
	tests := []struct {
		name    string
		options testpki.ClientOptions
	}{
		{name: "no SAN"},
		{name: "CN only", options: testpki.ClientOptions{CommonName: validURI.String()}},
		{name: "multiple URI", options: testpki.ClientOptions{URIs: []*url.URL{validURI, mustURL(t, "spiffe://aiops.example/runner/read/read-runner-02")}}},
		{name: "URI and DNS", options: testpki.ClientOptions{URIs: []*url.URL{validURI}, DNSNames: []string{"runner.test"}}},
		{name: "URI and IP", options: testpki.ClientOptions{URIs: []*url.URL{validURI}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}},
		{name: "URI and email", options: testpki.ClientOptions{URIs: []*url.URL{validURI}, EmailAddresses: []string{"runner@example.test"}}},
	}
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := mustClient(t, readCA, test.options, now)
			identity, authenticateErr := verifier.IdentityFromConnectionState(verifiedState(t, client, readCA, now))
			if authenticateErr == nil || identity.Valid() {
				t.Fatalf("IdentityFromConnectionState() = %#v, %v; want authentication failure", identity, authenticateErr)
			}
		})
	}
}

func TestIdentityIgnoresCommonNameWhenTheSingleURISANIsValid(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	client := mustClient(t, readCA, testpki.ClientOptions{
		CommonName: "spiffe://evil.example/runner/write/forged",
		URIs:       []*url.URL{mustURL(t, "spiffe://aiops.example/runner/read/read-runner-01")},
	}, now)
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	identity, err := verifier.IdentityFromConnectionState(verifiedState(t, client, readCA, now))
	if err != nil || identity.Pool() != runneridentity.PoolRead || identity.Instance() != "read-runner-01" {
		t.Fatalf("IdentityFromConnectionState() = %#v, %v", identity, err)
	}
}

func TestVerifierRejectsNonCanonicalTrustDomains(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	for _, trustDomain := range []string{
		"", "AIOPS.EXAMPLE", ".aiops.example", "aiops.example.", "aiops..example", "-aiops.example",
		"aiops-.example", "aiops_example", "aiops.example:8443", "user@aiops.example",
		"spiffe://aiops.example", "127.0.0.1", "::1", "aiops.example/path", "aiops.%65xample", "测试.example",
	} {
		t.Run(trustDomain, func(t *testing.T) {
			verifier, err := runneridentity.NewVerifier(runneridentity.Options{
				TrustDomain: trustDomain, ReadRoots: []*x509.Certificate{readCA.Certificate},
				WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
			})
			if err == nil || verifier != nil {
				t.Fatalf("NewVerifier(%q) = %#v, %v; want configuration rejection", trustDomain, verifier, err)
			}
		})
	}
}

func TestIdentityRejectsNonCanonicalSPIFFEURIs(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	for _, rawURI := range []string{
		"https://aiops.example/runner/read/read-runner-01",
		"SPIFFE://aiops.example/runner/read/read-runner-01",
		"spiffe://other.example/runner/read/read-runner-01",
		"spiffe://AIOPS.EXAMPLE/runner/read/read-runner-01",
		"spiffe://user@aiops.example/runner/read/read-runner-01",
		"spiffe://aiops.example:8443/runner/read/read-runner-01",
		"spiffe://aiops.example/runner/read/read-runner-01?scope=all",
		"spiffe://aiops.example/runner/read/read-runner-01#fragment",
		"spiffe://aiops.example/runner/read/read%2Drunner-01",
		"spiffe://aiops.example/runner/read/%2E%2E",
		"spiffe://aiops.example/runner/READ/read-runner-01",
		"spiffe://aiops.example/runner/admin/read-runner-01",
		"spiffe://aiops.example/runner/read",
		"spiffe://aiops.example/runner/read/",
		"spiffe://aiops.example/runner//read-runner-01",
		"spiffe://aiops.example/runner/read/../read-runner-01",
		"spiffe://aiops.example/runner/read/read-runner-01/extra",
		"spiffe://aiops.example/runner/read/read:runner",
	} {
		t.Run(rawURI, func(t *testing.T) {
			client := mustClient(t, readCA, testpki.ClientOptions{ExtraExtensions: []pkix.Extension{
				{Id: subjectAlternativeNameOID, Value: sanWithOnlyURI(t, rawURI)},
			}}, now)
			identity, authenticateErr := verifier.IdentityFromConnectionState(verifiedState(t, client, readCA, now))
			if authenticateErr == nil || identity.Valid() {
				t.Fatalf("IdentityFromConnectionState(%q) = %#v, %v; want authentication failure", rawURI, identity, authenticateErr)
			}
		})
	}
}

func TestVerifierRequiresDisjointExplicitReadAndWriteRootSets(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	client := mustClient(t, readCA, testpki.ClientOptions{
		URIs: []*url.URL{mustURL(t, "spiffe://aiops.example/runner/read/not-a-root")},
	}, now)
	reissuedReadCA, err := readCA.Reissue("runner-write-root-with-reused-key", now)
	if err != nil {
		t.Fatalf("Authority.Reissue() error = %v", err)
	}
	tests := []struct {
		name       string
		readRoots  []*x509.Certificate
		writeRoots []*x509.Certificate
		clock      func() time.Time
	}{
		{name: "missing READ roots", writeRoots: []*x509.Certificate{writeCA.Certificate}, clock: func() time.Time { return now }},
		{name: "missing WRITE roots", readRoots: []*x509.Certificate{readCA.Certificate}, clock: func() time.Time { return now }},
		{name: "same root in both pools", readRoots: []*x509.Certificate{readCA.Certificate}, writeRoots: []*x509.Certificate{readCA.Certificate}, clock: func() time.Time { return now }},
		{name: "same root key in distinct certificates", readRoots: []*x509.Certificate{readCA.Certificate}, writeRoots: []*x509.Certificate{reissuedReadCA.Certificate}, clock: func() time.Time { return now }},
		{name: "duplicate root in one pool", readRoots: []*x509.Certificate{readCA.Certificate, readCA.Certificate}, writeRoots: []*x509.Certificate{writeCA.Certificate}, clock: func() time.Time { return now }},
		{name: "leaf supplied as root", readRoots: []*x509.Certificate{client.Leaf}, writeRoots: []*x509.Certificate{writeCA.Certificate}, clock: func() time.Time { return now }},
		{name: "zero clock", readRoots: []*x509.Certificate{readCA.Certificate}, writeRoots: []*x509.Certificate{writeCA.Certificate}, clock: func() time.Time { return time.Time{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := runneridentity.NewVerifier(runneridentity.Options{
				TrustDomain: "aiops.example", ReadRoots: test.readRoots, WriteRoots: test.writeRoots, Clock: test.clock,
			})
			if err == nil || verifier != nil {
				t.Fatalf("NewVerifier() = %#v, %v; want configuration rejection", verifier, err)
			}
		})
	}
}

func TestIdentityBindsURIPoolToTheVerifiedRootPool(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	unknownCA := mustAuthority(t, "unregistered-root", now)
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	for _, test := range []struct {
		name      string
		authority *testpki.Authority
		uri       string
	}{
		{name: "READ URI on WRITE root", authority: writeCA, uri: "spiffe://aiops.example/runner/read/runner-01"},
		{name: "WRITE URI on READ root", authority: readCA, uri: "spiffe://aiops.example/runner/write/runner-01"},
		{name: "READ URI on unknown root", authority: unknownCA, uri: "spiffe://aiops.example/runner/read/runner-01"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := mustClient(t, test.authority, testpki.ClientOptions{URIs: []*url.URL{mustURL(t, test.uri)}}, now)
			identity, authenticateErr := verifier.IdentityFromConnectionState(verifiedState(t, client, test.authority, now))
			if authenticateErr == nil || identity.Valid() {
				t.Fatalf("IdentityFromConnectionState() = %#v, %v; want authentication failure", identity, authenticateErr)
			}
		})
	}
}

func TestIdentityAcceptsCurrentAndNextRootsWithinOnePool(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	currentReadCA := mustAuthority(t, "runner-read-current", now)
	nextReadCA := mustAuthority(t, "runner-read-next", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example",
		ReadRoots:   []*x509.Certificate{currentReadCA.Certificate, nextReadCA.Certificate},
		WriteRoots:  []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	for _, authority := range []*testpki.Authority{currentReadCA, nextReadCA} {
		client := mustClient(t, authority, testpki.ClientOptions{
			URIs: []*url.URL{mustURL(t, "spiffe://aiops.example/runner/read/read-runner-01")},
		}, now)
		identity, authenticateErr := verifier.IdentityFromConnectionState(verifiedState(t, client, authority, now))
		if authenticateErr != nil || identity.Pool() != runneridentity.PoolRead {
			t.Fatalf("IdentityFromConnectionState(rotation) = %#v, %v", identity, authenticateErr)
		}
	}
}

func TestIdentityRequiresALeastPrivilegeClientLeafCertificate(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	uri := []*url.URL{mustURL(t, "spiffe://aiops.example/runner/read/read-runner-01")}
	tests := []struct {
		name    string
		options testpki.ClientOptions
	}{
		{name: "CA leaf", options: testpki.ClientOptions{URIs: uri, IsCA: true}},
		{name: "missing digital signature", options: testpki.ClientOptions{URIs: uri, KeyUsage: x509.KeyUsageKeyEncipherment}},
		{name: "extra key usage", options: testpki.ClientOptions{URIs: uri, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}},
		{name: "any EKU", options: testpki.ClientOptions{URIs: uri, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}},
		{name: "server EKU", options: testpki.ClientOptions{URIs: uri, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}},
		{name: "mixed client and server EKU", options: testpki.ClientOptions{URIs: uri, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}},
		{name: "missing authority key ID", options: testpki.ClientOptions{URIs: uri, ExtraExtensions: []pkix.Extension{
			{Id: authorityKeyIdentifierOID, Value: []byte{0x30, 0x00}},
		}}},
		{name: "mismatched authority key ID", options: testpki.ClientOptions{URIs: uri, ExtraExtensions: []pkix.Extension{
			{Id: authorityKeyIdentifierOID, Value: authorityKeyIDExtension(t, []byte("not-the-signing-key"))},
		}}},
	}
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := mustClient(t, readCA, test.options, now)
			identity, authenticateErr := verifier.IdentityFromConnectionState(verifiedStateForAnyUsage(t, client, readCA, now))
			if authenticateErr == nil || identity.Valid() {
				t.Fatalf("IdentityFromConnectionState() = %#v, %v; want authentication failure", identity, authenticateErr)
			}
		})
	}
}

func authorityKeyIDExtension(t *testing.T, keyID []byte) []byte {
	t.Helper()
	identifier, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, Bytes: append([]byte(nil), keyID...),
	})
	if err != nil {
		t.Fatalf("marshal authority key identifier: %v", err)
	}
	encoded, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: identifier,
	})
	if err != nil {
		t.Fatalf("marshal authority key identifier sequence: %v", err)
	}
	return encoded
}

func TestIdentityIsRecomputedFromConnectionStateOnEveryRequest(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	observedAt := now
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	client := mustClient(t, readCA, testpki.ClientOptions{
		URIs:     []*url.URL{mustURL(t, "spiffe://aiops.example/runner/read/read-runner-01")},
		NotAfter: now.Add(time.Minute),
	}, now)
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return observedAt },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	state := verifiedState(t, client, readCA, now)
	if identity, err := verifier.IdentityFromConnectionState(state); err != nil || !identity.Valid() {
		t.Fatalf("IdentityFromConnectionState(first request) = %#v, %v", identity, err)
	}
	observedAt = now.Add(2 * time.Minute)
	if identity, err := verifier.IdentityFromConnectionState(state); err == nil || identity.Valid() {
		t.Fatalf("IdentityFromConnectionState(expired keepalive request) = %#v, %v; want failure", identity, err)
	}
	state.HandshakeComplete = false
	if identity, err := verifier.IdentityFromConnectionState(state); err == nil || identity.Valid() {
		t.Fatalf("IdentityFromConnectionState(incomplete handshake) = %#v, %v; want failure", identity, err)
	}
}

func TestIdentityRequiresAKISKIBindingAtEveryClientChainHop(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readRoot := mustAuthority(t, "runner-read-root", now)
	writeRoot := mustAuthority(t, "runner-write-root", now)
	validIntermediate := mustIntermediate(t, readRoot, "runner-read-intermediate", testpki.IntermediateOptions{}, now)
	missingAKIIntermediate := mustIntermediate(t, readRoot, "runner-read-missing-aki", testpki.IntermediateOptions{
		ExtraExtensions: []pkix.Extension{{Id: authorityKeyIdentifierOID, Value: []byte{0x30, 0x00}}},
	}, now)
	mismatchedAKIIntermediate := mustIntermediate(t, readRoot, "runner-read-mismatched-aki", testpki.IntermediateOptions{
		ExtraExtensions: []pkix.Extension{{Id: authorityKeyIdentifierOID, Value: authorityKeyIDExtension(t, []byte("wrong-root-key"))}},
	}, now)
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readRoot.Certificate},
		WriteRoots: []*x509.Certificate{writeRoot.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	for _, test := range []struct {
		name         string
		intermediate *testpki.Authority
		wantOK       bool
	}{
		{name: "valid intermediate chain", intermediate: validIntermediate, wantOK: true},
		{name: "intermediate missing AKI", intermediate: missingAKIIntermediate},
		{name: "intermediate AKI mismatch", intermediate: mismatchedAKIIntermediate},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := mustClient(t, test.intermediate, testpki.ClientOptions{
				URIs: []*url.URL{mustURL(t, "spiffe://aiops.example/runner/read/read-runner-01")},
			}, now)
			identity, authenticateErr := verifier.IdentityFromConnectionState(verifiedState(t, client, test.intermediate, now))
			if test.wantOK {
				if authenticateErr != nil || !identity.Valid() {
					t.Fatalf("IdentityFromConnectionState(valid intermediate) = %#v, %v", identity, authenticateErr)
				}
			} else if authenticateErr == nil || identity.Valid() {
				t.Fatalf("IdentityFromConnectionState(invalid intermediate) = %#v, %v; want failure", identity, authenticateErr)
			}
		})
	}
}

func sanWithOnlyURI(t *testing.T, rawURI string) []byte {
	t.Helper()
	uri, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(rawURI)})
	if err != nil {
		t.Fatalf("marshal URI GeneralName: %v", err)
	}
	encoded, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: uri,
	})
	if err != nil {
		t.Fatalf("marshal subject alternative name sequence: %v", err)
	}
	return encoded
}

func TestIdentityRejectsAnAdditionalUnmappedSANGeneralName(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	spiffeURI := "spiffe://aiops.example/runner/read/read-runner-01"
	client := mustClient(t, readCA, testpki.ClientOptions{ExtraExtensions: []pkix.Extension{
		{Id: subjectAlternativeNameOID, Value: sanWithRegisteredID(t, spiffeURI)},
	}}, now)
	if len(client.Leaf.URIs) != 1 || client.Leaf.URIs[0].String() != spiffeURI ||
		len(client.Leaf.DNSNames) != 0 || len(client.Leaf.IPAddresses) != 0 || len(client.Leaf.EmailAddresses) != 0 {
		t.Fatalf("test fixture was not parsed as one visible URI SAN: %#v", client.Leaf)
	}
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if identity, err := verifier.IdentityFromConnectionState(verifiedState(t, client, readCA, now)); err == nil || identity.Valid() {
		t.Fatalf("IdentityFromConnectionState(hidden SAN) = %#v, %v; want authentication failure", identity, err)
	}
}

func sanWithRegisteredID(t *testing.T, spiffeURI string) []byte {
	t.Helper()
	uri, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(spiffeURI)})
	if err != nil {
		t.Fatalf("marshal URI GeneralName: %v", err)
	}
	registeredID, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 8, Bytes: []byte{0x2a, 0x03},
	})
	if err != nil {
		t.Fatalf("marshal registered ID GeneralName: %v", err)
	}
	encoded, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(uri, registeredID...),
	})
	if err != nil {
		t.Fatalf("marshal subject alternative name sequence: %v", err)
	}
	return encoded
}

func TestServerTLSConfigIsPinnedToMutualTLS13AndHTTP11(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	serverCA := mustAuthority(t, "runner-server-root", now)
	server, err := serverCA.IssueServer("runner-gateway.test", now)
	if err != nil {
		t.Fatalf("Authority.IssueServer() error = %v", err)
	}
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	configuration, err := verifier.ServerTLSConfig(server.TLS)
	if err != nil {
		t.Fatalf("ServerTLSConfig() error = %v", err)
	}
	if configuration.MinVersion != tls.VersionTLS13 || configuration.MaxVersion != tls.VersionTLS13 ||
		configuration.ClientAuth != tls.RequireAndVerifyClientCert || configuration.ClientCAs == nil ||
		configuration.InsecureSkipVerify || len(configuration.NextProtos) != 1 || configuration.NextProtos[0] != "http/1.1" ||
		configuration.VerifyConnection == nil || configuration.VerifyPeerCertificate != nil || len(configuration.Certificates) != 1 {
		t.Fatalf("ServerTLSConfig() returned a weakened configuration: %#v", configuration)
	}
}

func TestServerTLSConfigRejectsUnsafeServerLeavesAndChains(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	serverCA := mustAuthority(t, "runner-server-root", now)
	otherCA := mustAuthority(t, "unrelated-server-root", now)
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	serverUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	tests := []struct {
		name        string
		certificate func(t *testing.T) tls.Certificate
	}{
		{name: "CA leaf", certificate: func(t *testing.T) tls.Certificate {
			return mustClient(t, serverCA, testpki.ClientOptions{IsCA: true, ExtKeyUsage: serverUsage}, now).TLS
		}},
		{name: "missing digital signature", certificate: func(t *testing.T) tls.Certificate {
			return mustClient(t, serverCA, testpki.ClientOptions{KeyUsage: x509.KeyUsageKeyEncipherment, ExtKeyUsage: serverUsage}, now).TLS
		}},
		{name: "extra key usage", certificate: func(t *testing.T) tls.Certificate {
			return mustClient(t, serverCA, testpki.ClientOptions{
				KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: serverUsage,
			}, now).TLS
		}},
		{name: "client EKU", certificate: func(t *testing.T) tls.Certificate {
			return mustClient(t, serverCA, testpki.ClientOptions{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, now).TLS
		}},
		{name: "mixed EKU", certificate: func(t *testing.T) tls.Certificate {
			return mustClient(t, serverCA, testpki.ClientOptions{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}, now).TLS
		}},
		{name: "expired leaf", certificate: func(t *testing.T) tls.Certificate {
			return mustClient(t, serverCA, testpki.ClientOptions{
				ExtKeyUsage: serverUsage, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour),
			}, now).TLS
		}},
		{name: "not yet valid leaf", certificate: func(t *testing.T) tls.Certificate {
			return mustClient(t, serverCA, testpki.ClientOptions{
				ExtKeyUsage: serverUsage, NotBefore: now.Add(time.Hour), NotAfter: now.Add(2 * time.Hour),
			}, now).TLS
		}},
		{name: "malformed chain certificate", certificate: func(t *testing.T) tls.Certificate {
			value := mustServer(t, serverCA, "runner-gateway.test", now).TLS
			value.Certificate = append(value.Certificate, []byte{0x01, 0x02, 0x03})
			return value
		}},
		{name: "non CA issuer", certificate: func(t *testing.T) tls.Certificate {
			value := mustServer(t, serverCA, "runner-gateway.test", now).TLS
			nonCA := mustClient(t, serverCA, testpki.ClientOptions{ExtKeyUsage: serverUsage}, now)
			value.Certificate[1] = append([]byte(nil), nonCA.Leaf.Raw...)
			return value
		}},
		{name: "issuer does not sign leaf", certificate: func(t *testing.T) tls.Certificate {
			value := mustServer(t, serverCA, "runner-gateway.test", now).TLS
			value.Certificate[1] = append([]byte(nil), otherCA.Certificate.Raw...)
			return value
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration, configureErr := verifier.ServerTLSConfig(test.certificate(t))
			if configureErr == nil || configuration != nil {
				t.Fatalf("ServerTLSConfig() = %#v, %v; want unsafe server certificate rejection", configuration, configureErr)
			}
		})
	}
}

func TestServerTLSConfigRequiresAKISKIBindingAtEveryServerChainHop(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readRoot := mustAuthority(t, "runner-read-root", now)
	writeRoot := mustAuthority(t, "runner-write-root", now)
	serverRoot := mustAuthority(t, "runner-server-root", now)
	validIntermediate := mustIntermediate(t, serverRoot, "runner-server-intermediate", testpki.IntermediateOptions{}, now)
	missingAKIIntermediate := mustIntermediate(t, serverRoot, "runner-server-missing-aki", testpki.IntermediateOptions{
		ExtraExtensions: []pkix.Extension{{Id: authorityKeyIdentifierOID, Value: []byte{0x30, 0x00}}},
	}, now)
	mismatchedAKIIntermediate := mustIntermediate(t, serverRoot, "runner-server-mismatched-aki", testpki.IntermediateOptions{
		ExtraExtensions: []pkix.Extension{{Id: authorityKeyIdentifierOID, Value: authorityKeyIDExtension(t, []byte("wrong-root-key"))}},
	}, now)
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readRoot.Certificate},
		WriteRoots: []*x509.Certificate{writeRoot.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	missingLeafAKI := mustClient(t, validIntermediate, testpki.ClientOptions{
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{{Id: authorityKeyIdentifierOID, Value: []byte{0x30, 0x00}}},
	}, now).TLS
	mismatchedLeafAKI := mustClient(t, validIntermediate, testpki.ClientOptions{
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{{Id: authorityKeyIdentifierOID, Value: authorityKeyIDExtension(t, []byte("wrong-intermediate-key"))}},
	}, now).TLS
	for _, test := range []struct {
		name        string
		certificate tls.Certificate
		wantOK      bool
	}{
		{name: "valid intermediate chain", certificate: mustServer(t, validIntermediate, "runner-gateway.test", now).TLS, wantOK: true},
		{name: "intermediate missing AKI", certificate: mustServer(t, missingAKIIntermediate, "runner-gateway.test", now).TLS},
		{name: "intermediate AKI mismatch", certificate: mustServer(t, mismatchedAKIIntermediate, "runner-gateway.test", now).TLS},
		{name: "leaf missing AKI", certificate: missingLeafAKI},
		{name: "leaf AKI mismatch", certificate: mismatchedLeafAKI},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration, configureErr := verifier.ServerTLSConfig(test.certificate)
			if test.wantOK {
				if configureErr != nil || configuration == nil {
					t.Fatalf("ServerTLSConfig(valid intermediate) = %#v, %v", configuration, configureErr)
				}
			} else if configureErr == nil || configuration != nil {
				t.Fatalf("ServerTLSConfig(invalid AKI/SKI chain) unexpectedly succeeded")
			}
		})
	}
}

func TestServerTLSConfigDoesNotShareMutableCertificateSlices(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	serverCA := mustAuthority(t, "runner-server-root", now)
	server := mustServer(t, serverCA, "runner-gateway.test", now).TLS
	server.OCSPStaple = []byte{0x01, 0x02}
	server.SignedCertificateTimestamps = [][]byte{{0x03, 0x04}}
	server.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	first, err := verifier.ServerTLSConfig(server)
	if err != nil {
		t.Fatalf("ServerTLSConfig(first) error = %v", err)
	}
	second, err := verifier.ServerTLSConfig(server)
	if err != nil {
		t.Fatalf("ServerTLSConfig(second) error = %v", err)
	}
	wantLeafFirstByte := second.Certificates[0].Certificate[0][0]
	wantOCSPFirstByte := second.Certificates[0].OCSPStaple[0]
	wantSCTFirstByte := second.Certificates[0].SignedCertificateTimestamps[0][0]
	wantSignatureScheme := second.Certificates[0].SupportedSignatureAlgorithms[0]
	wantCommonName := second.Certificates[0].Leaf.Subject.CommonName

	server.Certificate[0][0] ^= 0xff
	server.OCSPStaple[0] ^= 0xff
	server.SignedCertificateTimestamps[0][0] ^= 0xff
	server.SupportedSignatureAlgorithms[0] = tls.PSSWithSHA256
	server.Leaf.Subject.CommonName = "mutated-input"
	first.Certificates[0].Certificate[0][0] ^= 0xff
	first.Certificates[0].OCSPStaple[0] ^= 0xff
	first.Certificates[0].SignedCertificateTimestamps[0][0] ^= 0xff
	first.Certificates[0].SupportedSignatureAlgorithms[0] = tls.PSSWithSHA256
	first.Certificates[0].Leaf.Subject.CommonName = "mutated-first-config"

	got := second.Certificates[0]
	if got.Certificate[0][0] != wantLeafFirstByte || got.OCSPStaple[0] != wantOCSPFirstByte ||
		got.SignedCertificateTimestamps[0][0] != wantSCTFirstByte ||
		got.SupportedSignatureAlgorithms[0] != wantSignatureScheme || got.Leaf.Subject.CommonName != wantCommonName {
		t.Fatalf("second ServerTLSConfig() shared mutable certificate state: %#v", got)
	}
}

func TestServerTLSConfigEnforcesTheRunnerIdentityDuringARealHandshake(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	unknownCA := mustAuthority(t, "runner-unknown-root", now)
	serverCA := mustAuthority(t, "runner-server-root", now)
	server := mustServer(t, serverCA, "runner-gateway.test", now)
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	serverConfiguration, err := verifier.ServerTLSConfig(server.TLS)
	if err != nil {
		t.Fatalf("ServerTLSConfig() error = %v", err)
	}
	validRead := mustClient(t, readCA, testpki.ClientOptions{
		URIs: []*url.URL{mustURL(t, "spiffe://aiops.example/runner/read/read-runner-01")},
	}, now)
	validWrite := mustClient(t, writeCA, testpki.ClientOptions{
		URIs: []*url.URL{mustURL(t, "spiffe://aiops.example/runner/write/write-runner-01")},
	}, now)
	wrongEKU := mustClient(t, readCA, testpki.ClientOptions{
		URIs:        []*url.URL{mustURL(t, "spiffe://aiops.example/runner/read/read-runner-02")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, now)
	crossPool := mustClient(t, writeCA, testpki.ClientOptions{
		URIs: []*url.URL{mustURL(t, "spiffe://aiops.example/runner/read/read-runner-03")},
	}, now)
	unknown := mustClient(t, unknownCA, testpki.ClientOptions{
		URIs: []*url.URL{mustURL(t, "spiffe://aiops.example/runner/read/read-runner-04")},
	}, now)
	tests := []struct {
		name       string
		client     *tls.Certificate
		maxVersion uint16
		wantOK     bool
	}{
		{name: "READ", client: &validRead.TLS, maxVersion: tls.VersionTLS13, wantOK: true},
		{name: "WRITE", client: &validWrite.TLS, maxVersion: tls.VersionTLS13, wantOK: true},
		{name: "no certificate", maxVersion: tls.VersionTLS13},
		{name: "unknown root", client: &unknown.TLS, maxVersion: tls.VersionTLS13},
		{name: "wrong EKU", client: &wrongEKU.TLS, maxVersion: tls.VersionTLS13},
		{name: "cross pool", client: &crossPool.TLS, maxVersion: tls.VersionTLS13},
		{name: "TLS 1.2", client: &validRead.TLS, maxVersion: tls.VersionTLS12},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientConfiguration := &tls.Config{
				RootCAs: serverCA.CertPool(), ServerName: "runner-gateway.test",
				MinVersion: tls.VersionTLS12, MaxVersion: test.maxVersion, NextProtos: []string{"http/1.1"},
			}
			if test.client != nil {
				clientConfiguration.Certificates = []tls.Certificate{*test.client}
			}
			state, handshakeErr := performTLSHandshake(t, serverConfiguration, clientConfiguration)
			if test.wantOK {
				if handshakeErr != nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "http/1.1" {
					t.Fatalf("TLS handshake state = %#v, error = %v", state, handshakeErr)
				}
				identity, identityErr := verifier.IdentityFromConnectionState(state)
				if identityErr != nil || !identity.Valid() {
					t.Fatalf("IdentityFromConnectionState(handshake) = %#v, %v", identity, identityErr)
				}
			} else if handshakeErr == nil {
				t.Fatalf("TLS handshake unexpectedly succeeded: %#v", state)
			}
		})
	}
}

func TestServerTLSConfigUsesVerifierClockDuringARealHandshake(t *testing.T) {
	verifierNow := time.Date(2040, time.January, 2, 3, 4, 5, 0, time.UTC)
	readCA := mustAuthority(t, "future-runner-read-root", verifierNow)
	writeCA := mustAuthority(t, "future-runner-write-root", verifierNow)
	serverCA := mustAuthority(t, "future-runner-server-root", verifierNow)
	server := mustServer(t, serverCA, "runner-gateway.test", verifierNow)
	client := mustClient(t, readCA, testpki.ClientOptions{
		URIs: []*url.URL{mustURL(t, "spiffe://aiops.example/runner/read/future-read-runner")},
	}, verifierNow)
	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example", ReadRoots: []*x509.Certificate{readCA.Certificate},
		WriteRoots: []*x509.Certificate{writeCA.Certificate}, Clock: func() time.Time { return verifierNow },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	serverConfiguration, err := verifier.ServerTLSConfig(server.TLS)
	if err != nil {
		t.Fatalf("ServerTLSConfig() error = %v", err)
	}
	if serverConfiguration.Time == nil || !serverConfiguration.Time().Equal(verifierNow) {
		t.Fatalf("ServerTLSConfig().Time does not use verifier clock")
	}
	clientConfiguration := &tls.Config{
		RootCAs: serverCA.CertPool(), ServerName: "runner-gateway.test", Certificates: []tls.Certificate{client.TLS},
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"},
		Time: func() time.Time { return verifierNow },
	}
	state, err := performTLSHandshake(t, serverConfiguration, clientConfiguration)
	if err != nil || !state.HandshakeComplete {
		t.Fatalf("future-clock TLS handshake state = %#v, error = %v", state, err)
	}
}

func TestIdentityFromConnectionStateReturnsCanonicalReadIdentityAndCertificateEvidence(t *testing.T) {
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustAuthority(t, "runner-read-root", now)
	writeCA := mustAuthority(t, "runner-write-root", now)
	spiffeURI := mustURL(t, "spiffe://aiops.example/runner/read/read-runner-01")
	client := mustClient(t, readCA, testpki.ClientOptions{URIs: []*url.URL{spiffeURI}}, now)

	verifier, err := runneridentity.NewVerifier(runneridentity.Options{
		TrustDomain: "aiops.example",
		ReadRoots:   []*x509.Certificate{readCA.Certificate},
		WriteRoots:  []*x509.Certificate{writeCA.Certificate},
		Clock:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	identity, err := verifier.IdentityFromConnectionState(verifiedState(t, client, readCA, now))
	if err != nil {
		t.Fatalf("IdentityFromConnectionState() error = %v", err)
	}
	if !identity.Valid() || identity.TrustDomain() != "aiops.example" || identity.Pool() != runneridentity.PoolRead ||
		identity.Instance() != "read-runner-01" || identity.SPIFFEURI() != spiffeURI.String() {
		t.Fatalf("IdentityFromConnectionState() = %#v", identity)
	}

	leafDigest := sha256.Sum256(client.Leaf.Raw)
	spkiDigest := sha256.Sum256(client.Leaf.RawSubjectPublicKeyInfo)
	rootDigest := sha256.Sum256(readCA.Certificate.Raw)
	evidence := identity.Evidence()
	if !evidence.Valid() || evidence.LeafSHA256() != hex.EncodeToString(leafDigest[:]) ||
		evidence.SPKISHA256() != hex.EncodeToString(spkiDigest[:]) ||
		evidence.SerialHex() != hex.EncodeToString(client.Leaf.SerialNumber.Bytes()) ||
		evidence.AuthorityKeyIDHex() != hex.EncodeToString(client.Leaf.AuthorityKeyId) ||
		evidence.RootSHA256() != hex.EncodeToString(rootDigest[:]) || evidence.RootPool() != runneridentity.PoolRead ||
		!evidence.NotAfter().Equal(client.Leaf.NotAfter) {
		t.Fatalf("Identity.Evidence() = %#v", evidence)
	}
}

func mustAuthority(t *testing.T, name string, now time.Time) *testpki.Authority {
	t.Helper()
	authority, err := testpki.NewAuthority(name, now)
	if err != nil {
		t.Fatalf("testpki.NewAuthority(%q) error = %v", name, err)
	}
	return authority
}

func mustIntermediate(
	t *testing.T,
	parent *testpki.Authority,
	name string,
	options testpki.IntermediateOptions,
	now time.Time,
) *testpki.Authority {
	t.Helper()
	authority, err := parent.IssueIntermediate(name, options, now)
	if err != nil {
		t.Fatalf("Authority.IssueIntermediate(%q) error = %v", name, err)
	}
	return authority
}

func mustClient(t *testing.T, authority *testpki.Authority, options testpki.ClientOptions, now time.Time) testpki.Certificate {
	t.Helper()
	certificate, err := authority.IssueClient(options, now)
	if err != nil {
		t.Fatalf("Authority.IssueClient() error = %v", err)
	}
	return certificate
}

func mustServer(t *testing.T, authority *testpki.Authority, serverName string, now time.Time) testpki.Certificate {
	t.Helper()
	certificate, err := authority.IssueServer(serverName, now)
	if err != nil {
		t.Fatalf("Authority.IssueServer() error = %v", err)
	}
	return certificate
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	value, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", raw, err)
	}
	return value
}

func verifiedState(t *testing.T, certificate testpki.Certificate, authority *testpki.Authority, now time.Time) tls.ConnectionState {
	t.Helper()
	return verifiedStateForUsage(t, certificate, authority, now, x509.ExtKeyUsageClientAuth)
}

func verifiedStateForAnyUsage(t *testing.T, certificate testpki.Certificate, authority *testpki.Authority, now time.Time) tls.ConnectionState {
	t.Helper()
	return verifiedStateForUsage(t, certificate, authority, now, x509.ExtKeyUsageAny)
}

func verifiedStateForUsage(
	t *testing.T,
	certificate testpki.Certificate,
	authority *testpki.Authority,
	now time.Time,
	usage x509.ExtKeyUsage,
) tls.ConnectionState {
	t.Helper()
	intermediates := x509.NewCertPool()
	peers := []*x509.Certificate{certificate.Leaf}
	for _, raw := range certificate.TLS.Certificate[1:] {
		parsed, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatalf("parse test certificate chain: %v", err)
		}
		peers = append(peers, parsed)
		intermediates.AddCert(parsed)
	}
	chains, err := certificate.Leaf.Verify(x509.VerifyOptions{
		Roots: authority.CertPool(), Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{usage},
	})
	if err != nil {
		t.Fatalf("verify test certificate for fixture construction: %v", err)
	}
	return tls.ConnectionState{
		Version: tls.VersionTLS13, HandshakeComplete: true,
		PeerCertificates: peers,
		VerifiedChains:   chains,
	}
}

func performTLSHandshake(t *testing.T, serverConfiguration, clientConfiguration *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer listener.Close()
	type result struct {
		state tls.ConnectionState
		err   error
	}
	serverResult := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- result{err: acceptErr}
			return
		}
		defer connection.Close()
		server := tls.Server(connection, serverConfiguration)
		handshakeErr := server.HandshakeContext(ctx)
		serverResult <- result{state: server.ConnectionState(), err: handshakeErr}
	}()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		return tls.ConnectionState{}, err
	}
	client := tls.Client(connection, clientConfiguration)
	clientErr := client.HandshakeContext(ctx)
	_ = connection.Close()
	resultValue := <-serverResult
	if resultValue.err != nil {
		return resultValue.state, resultValue.err
	}
	if clientErr != nil {
		return resultValue.state, clientErr
	}
	return resultValue.state, nil
}
