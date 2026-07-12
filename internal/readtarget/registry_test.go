package readtarget_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readtarget"
)

const (
	tenantID      = "10000000-0000-4000-8000-000000000001"
	workspaceID   = "20000000-0000-4000-8000-000000000002"
	environmentID = "30000000-0000-4000-8000-000000000003"
	serviceID     = "40000000-0000-4000-8000-000000000004"
)

var contentReferencePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,59}-v1-[a-f0-9]{64}$`)

func TestBuildTargetRefDerivesStableContentAddress(t *testing.T) {
	definition := validDefinition(t, readconnector.KindPrometheus)

	first, err := readtarget.BuildTargetRef("prometheus-staging", definition)
	if err != nil {
		t.Fatalf("BuildTargetRef() error = %v", err)
	}
	second, err := readtarget.BuildTargetRef("prometheus-staging", definition)
	if err != nil {
		t.Fatalf("BuildTargetRef(second) error = %v", err)
	}
	if first != second || !contentReferencePattern.MatchString(first) {
		t.Fatalf("BuildTargetRef() = %q / %q", first, second)
	}
}

func TestTargetContentAddressBindsEverySecurityRelevantField(t *testing.T) {
	original := validDefinition(t, readconnector.KindPrometheus)
	originalRef := mustBuildTargetRef(t, "prometheus-staging", original)
	tests := map[string]func(*readtarget.Definition){
		"scope": func(definition *readtarget.Definition) {
			definition.Scope.EnvironmentID = "30000000-0000-4000-8000-000000000099"
		},
		"kind": func(definition *readtarget.Definition) {
			definition.Kind = readconnector.KindVictoriaLogs
		},
		"origin and server name": func(definition *readtarget.Definition) {
			definition.Endpoint.Origin = "https://logs.staging.internal:9443"
			definition.Endpoint.ServerName = "logs.staging.internal"
		},
		"CA roots": func(definition *readtarget.Definition) {
			definition.Endpoint.CABundleFile = writeRootBundle(t, "root-b")
		},
		"credential role": func(definition *readtarget.Definition) {
			definition.CredentialRoleRef = "metrics-reader-v1-" + repeatHex("c")
		},
		"network policy": func(definition *readtarget.Definition) {
			definition.NetworkPolicyRef = "metrics-egress-v1-" + repeatHex("d")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			changedRef, err := readtarget.BuildTargetRef("prometheus-staging", changed)
			if err != nil || changedRef == originalRef {
				t.Fatalf("BuildTargetRef(changed %s) = %q, %v; original=%q", name, changedRef, err, originalRef)
			}

			changed.TargetRef = originalRef
			registry, err := readtarget.LoadFile(writeManifest(t, []readtarget.Definition{changed}))
			if registry != nil || !errors.Is(err, readtarget.ErrManifestDefinition) {
				t.Fatalf("LoadFile(old ref after %s drift) = %#v, %v", name, registry, err)
			}
		})
	}
}

func TestLoadFileResolvesOneExactImmutableTarget(t *testing.T) {
	definition := validDefinition(t, readconnector.KindPrometheus)
	definition.TargetRef = mustBuildTargetRef(t, "prometheus-staging", definition)
	path := writeManifest(t, []readtarget.Definition{definition})

	registry, err := readtarget.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if registry == nil || !registry.Ready() || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(registry.Digest()) {
		t.Fatalf("LoadFile() registry = %#v digest=%q", registry, registry.Digest())
	}
	target, err := registry.Resolve(context.Background(), validTaskScope(), readconnector.KindPrometheus, definition.TargetRef)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if target.TargetRef() != definition.TargetRef || target.Kind() != definition.Kind ||
		target.Digest() != definition.TargetRef[len(definition.TargetRef)-64:] ||
		target.CredentialRoleRef() != definition.CredentialRoleRef ||
		target.NetworkPolicyRef() != definition.NetworkPolicyRef {
		t.Fatalf("Resolve() target identity mismatch: %#v", target)
	}
	origin := target.OriginURL()
	tlsConfiguration := target.TLSConfig()
	if origin == nil || origin.String() != definition.Endpoint.Origin || tlsConfiguration == nil ||
		tlsConfiguration.ServerName != definition.Endpoint.ServerName || tlsConfiguration.RootCAs == nil ||
		tlsConfiguration.MinVersion != 0x0304 || tlsConfiguration.MaxVersion != 0x0304 ||
		len(tlsConfiguration.NextProtos) != 1 || tlsConfiguration.NextProtos[0] != "http/1.1" ||
		!tlsConfiguration.SessionTicketsDisabled || tlsConfiguration.InsecureSkipVerify {
		t.Fatalf("Resolve() returned unsafe endpoint/TLS configuration")
	}
	origin.Host = "mutated.invalid:443"
	tlsConfiguration.ServerName = "mutated.invalid"
	tlsConfiguration.RootCAs = nil
	tlsConfiguration.NextProtos[0] = "h2"
	second, err := registry.Resolve(context.Background(), validTaskScope(), readconnector.KindPrometheus, definition.TargetRef)
	if err != nil || second.OriginURL().String() != definition.Endpoint.Origin ||
		second.TLSConfig().ServerName != definition.Endpoint.ServerName || second.TLSConfig().RootCAs == nil ||
		len(second.TLSConfig().NextProtos) != 1 || second.TLSConfig().NextProtos[0] != "http/1.1" {
		t.Fatalf("caller mutation changed immutable target: %#v / %v", second, err)
	}
}

func TestResolveRequiresExactMapping(t *testing.T) {
	definition := validDefinition(t, readconnector.KindPrometheus)
	definition.TargetRef = mustBuildTargetRef(t, "prometheus-staging", definition)
	registry, err := readtarget.LoadFile(writeManifest(t, []readtarget.Definition{definition}))
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}

	scope := validTaskScope()
	scope.MappingStatus = domain.MappingAmbiguous
	if _, err := registry.Resolve(context.Background(), scope, definition.Kind, definition.TargetRef); !errors.Is(err, readtarget.ErrTargetRejected) {
		t.Fatalf("Resolve(ambiguous mapping) error = %v, want ErrTargetRejected", err)
	}
}

func TestResolveRejectsTypedNilContext(t *testing.T) {
	definition := validDefinition(t, readconnector.KindPrometheus)
	definition.TargetRef = mustBuildTargetRef(t, "prometheus-staging", definition)
	registry, err := readtarget.LoadFile(writeManifest(t, []readtarget.Definition{definition}))
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	var typedNil *testContext
	_, err = registry.Resolve(typedNil, validTaskScope(), definition.Kind, definition.TargetRef)
	if !errors.Is(err, readtarget.ErrTargetRejected) {
		t.Fatalf("Resolve(typed nil context) error = %v, want ErrTargetRejected", err)
	}
}

func TestBuildTargetRefRejectsSingleLabelDNSAndSensitiveReferenceBases(t *testing.T) {
	valid := validDefinition(t, readconnector.KindPrometheus)
	tests := map[string]func(*readtarget.Definition){
		"single-label DNS": func(definition *readtarget.Definition) {
			definition.Endpoint.Origin = "https://localhost:8443"
			definition.Endpoint.ServerName = "localhost"
		},
		"credential secret": func(definition *readtarget.Definition) {
			definition.CredentialRoleRef = "secret-reader-v1-" + repeatHex("a")
		},
		"credential disguised token": func(definition *readtarget.Definition) {
			definition.CredentialRoleRef = "api_token_reader-v1-" + repeatHex("a")
		},
		"network host": func(definition *readtarget.Definition) {
			definition.NetworkPolicyRef = "target-host-egress-v1-" + repeatHex("b")
		},
		"network URL": func(definition *readtarget.Definition) {
			definition.NetworkPolicyRef = "metrics-url-policy-v1-" + repeatHex("b")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			definition := valid
			mutate(&definition)
			if targetRef, err := readtarget.BuildTargetRef("safe-target", definition); targetRef != "" ||
				!errors.Is(err, readtarget.ErrInvalidDefinition) {
				t.Fatalf("BuildTargetRef() = %q, %v; want rejection", targetRef, err)
			}
		})
	}
}

func TestBuildTargetRefCanonicalizesMultiRootPEMOrderAndWhitespace(t *testing.T) {
	rootA := newRootPEM(t, "root-a", 11)
	rootB := newRootPEM(t, "root-b", 12)
	first := validDefinition(t, readconnector.KindPrometheus)
	first.Endpoint.CABundleFile = writeBundle(t, "roots-ab.pem", rootA, []byte("\n"), rootB)
	second := first
	second.Endpoint.CABundleFile = writeBundle(t, "roots-ba.pem", []byte("\n\t"), rootB, []byte("\r\n"), rootA, []byte("\n"))

	firstRef, firstErr := readtarget.BuildTargetRef("prometheus-staging", first)
	secondRef, secondErr := readtarget.BuildTargetRef("prometheus-staging", second)
	if firstErr != nil || secondErr != nil || firstRef != secondRef {
		t.Fatalf("BuildTargetRef(multi-root) = %q/%v, %q/%v", firstRef, firstErr, secondRef, secondErr)
	}
}

func TestBuildTargetRefRejectsInvalidOrUnsafeCABundles(t *testing.T) {
	now := time.Now().UTC()
	leaf := newCertificatePEM(t, "leaf", 20, true, func(certificate *x509.Certificate) {
		certificate.IsCA = false
		certificate.KeyUsage = x509.KeyUsageDigitalSignature
	})
	noCertSign := newCertificatePEM(t, "no-cert-sign", 21, true, func(certificate *x509.Certificate) {
		certificate.KeyUsage = x509.KeyUsageDigitalSignature
	})
	expired := newCertificatePEM(t, "expired", 22, true, func(certificate *x509.Certificate) {
		certificate.NotBefore = now.Add(-2 * time.Hour)
		certificate.NotAfter = now.Add(-time.Hour)
	})
	notYetValid := newCertificatePEM(t, "future", 23, true, func(certificate *x509.Certificate) {
		certificate.NotBefore = now.Add(time.Hour)
		certificate.NotAfter = now.Add(2 * time.Hour)
	})
	notSelfSigned := newCertificatePEM(t, "not-self-signed", 24, false, nil)
	issuerMismatch := newIssuerMismatchPEM(t, "subject-root", "different-issuer", 29)
	validRoot := newRootPEM(t, "valid-root", 25)
	oversizedDER := newCertificatePEM(t, "oversized-der", 28, true, func(certificate *x509.Certificate) {
		certificate.ExtraExtensions = []pkix.Extension{{
			Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: bytes.Repeat([]byte("x"), 17<<10),
		}}
	})
	tooMany := make([][]byte, 0, 17)
	for index := range 17 {
		tooMany = append(tooMany, newRootPEM(t, fmt.Sprintf("root-%d", index), int64(100+index)))
	}
	tests := map[string][]byte{
		"empty":              nil,
		"garbage":            []byte("ca-garbage-canary"),
		"private key":        pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("canary")}),
		"invalid DER":        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("canary")}),
		"leaf":               leaf,
		"no cert sign":       noCertSign,
		"expired":            expired,
		"not yet valid":      notYetValid,
		"not self-signed":    notSelfSigned,
		"issuer mismatch":    issuerMismatch,
		"duplicate":          bytes.Join([][]byte{validRoot, validRoot}, nil),
		"trailing garbage":   append(append([]byte(nil), validRoot...), []byte("canary")...),
		"too many":           bytes.Join(tooMany, nil),
		"oversized bundle":   bytes.Join([][]byte{validRoot, bytes.Repeat([]byte(" "), 70<<10), newRootPEM(t, "second-root", 27)}, nil),
		"oversized root DER": oversizedDER,
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			definition := validDefinition(t, readconnector.KindPrometheus)
			definition.Endpoint.CABundleFile = writeBundle(t, "invalid-ca.pem", contents)
			targetRef, err := readtarget.BuildTargetRef("prometheus-staging", definition)
			if targetRef != "" || !errors.Is(err, readtarget.ErrInvalidDefinition) || strings.Contains(fmt.Sprint(err), "canary") {
				t.Fatalf("BuildTargetRef() = %q, %v; want low-sensitive rejection", targetRef, err)
			}
		})
	}

	t.Run("unsafe file metadata", func(t *testing.T) {
		root := newRootPEM(t, "metadata-root", 26)
		directory := t.TempDir()
		target := filepath.Join(directory, "root.pem")
		if err := os.WriteFile(target, root, 0o600); err != nil {
			t.Fatal(err)
		}
		symlink := filepath.Join(directory, "root-link.pem")
		if err := os.Symlink(target, symlink); err != nil {
			t.Fatal(err)
		}
		hardlink := filepath.Join(directory, "root-hardlink.pem")
		if err := os.Link(target, hardlink); err != nil {
			t.Fatal(err)
		}
		groupWritable := filepath.Join(directory, "root-mode.pem")
		if err := os.WriteFile(groupWritable, root, 0o620); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(groupWritable, 0o620); err != nil {
			t.Fatal(err)
		}
		for name, path := range map[string]string{
			"relative": "root.pem", "symlink": symlink, "hardlink": hardlink, "group writable": groupWritable,
		} {
			t.Run(name, func(t *testing.T) {
				definition := validDefinition(t, readconnector.KindPrometheus)
				definition.Endpoint.CABundleFile = path
				if _, err := readtarget.BuildTargetRef("prometheus-staging", definition); !errors.Is(err, readtarget.ErrInvalidDefinition) {
					t.Fatalf("BuildTargetRef() error = %v, want ErrInvalidDefinition", err)
				}
			})
		}
	})
}

func validDefinition(t *testing.T, kind readconnector.Kind) readtarget.Definition {
	t.Helper()
	return readtarget.Definition{
		Scope: readtarget.Scope{
			TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID,
		},
		Kind: kind,
		Endpoint: readtarget.Endpoint{
			Origin: "https://metrics.staging.internal:8443", ServerName: "metrics.staging.internal",
			CABundleFile: writeRootBundle(t, "root-a"),
		},
		CredentialRoleRef: "metrics-reader-v1-" + repeatHex("a"),
		NetworkPolicyRef:  "metrics-egress-v1-" + repeatHex("b"),
	}
}

func validTaskScope() investigation.TaskSpecScope {
	return investigation.TaskSpecScope{
		TenantID: tenantID, WorkspaceID: workspaceID, EnvironmentID: environmentID,
		ServiceID: serviceID, MappingStatus: domain.MappingExact,
	}
}

func mustBuildTargetRef(t *testing.T, base string, definition readtarget.Definition) string {
	t.Helper()
	targetRef, err := readtarget.BuildTargetRef(base, definition)
	if err != nil {
		t.Fatalf("BuildTargetRef() error = %v", err)
	}
	return targetRef
}

func writeManifest(t *testing.T, definitions []readtarget.Definition) string {
	t.Helper()
	document := struct {
		SchemaVersion string                  `json:"schema_version"`
		Targets       []readtarget.Definition `json:"targets"`
	}{SchemaVersion: readtarget.ManifestSchemaVersion, Targets: definitions}
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "read-targets.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func writeRootBundle(t *testing.T, commonName string) string {
	t.Helper()
	return writeBundle(t, commonName+".pem", newRootPEM(t, commonName, 1))
}

func newRootPEM(t *testing.T, commonName string, serial int64) []byte {
	t.Helper()
	return newCertificatePEM(t, commonName, serial, true, nil)
}

func newCertificatePEM(
	t *testing.T,
	commonName string,
	serial int64,
	selfSigned bool,
	mutate func(*x509.Certificate),
) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	if mutate != nil {
		mutate(template)
	}
	signer := privateKey
	if !selfSigned {
		_, signer, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey(signer) error = %v", err)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, signer)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newIssuerMismatchPEM(t *testing.T, subject, issuer string, serial int64) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: subject},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	parent := *template
	parent.Subject = pkix.Name{CommonName: issuer}
	parent.PublicKeyAlgorithm = x509.Ed25519
	parent.PublicKey = publicKey
	der, err := x509.CreateCertificate(rand.Reader, template, &parent, publicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeBundle(t *testing.T, name string, blocks ...[]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	contents := bytes.Join(blocks, nil)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func repeatHex(character string) string {
	result := ""
	for range 64 {
		result += character
	}
	return result
}

type testContext struct{}

func (*testContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*testContext) Done() <-chan struct{}       { return nil }
func (*testContext) Err() error                  { return nil }
func (*testContext) Value(any) any               { return nil }
