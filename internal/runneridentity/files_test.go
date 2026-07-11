package runneridentity_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/seaworld008/aiops-system/internal/runneridentity"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

const maximumRunnerIdentityFileSize = 1 << 20

func TestLoadFilesBuildsCurrentPinnedMutualTLSConfiguration(t *testing.T) {
	fixture := newFileFixture(t)

	verifier, configuration, err := runneridentity.LoadFiles(fixture.options)
	if err != nil {
		t.Fatalf("LoadFiles() error = %v", err)
	}
	if verifier == nil || configuration == nil || configuration.MinVersion != tls.VersionTLS13 ||
		configuration.MaxVersion != tls.VersionTLS13 || configuration.ClientAuth != tls.RequireAndVerifyClientCert ||
		configuration.ClientCAs == nil || len(configuration.Certificates) != 1 || configuration.VerifyConnection == nil ||
		configuration.Time == nil || !configuration.Time().Equal(fixture.now) {
		t.Fatalf("LoadFiles() returned unsafe configuration: verifier=%#v tls=%#v", verifier, configuration)
	}
	if len(configuration.Certificates[0].Certificate) != len(fixture.server.TLS.Certificate) ||
		configuration.Certificates[0].Leaf == nil ||
		!configuration.Certificates[0].Leaf.Equal(fixture.server.Leaf) {
		t.Fatalf("LoadFiles() did not retain the validated current server chain: %#v", configuration.Certificates[0])
	}
}

func TestLoadFilesAcceptsAppOwnedMode0400StagingFiles(t *testing.T) {
	fixture := newFileFixture(t)
	for _, path := range []string{
		fixture.options.ServerCertFile,
		fixture.options.ServerKeyFile,
		fixture.options.ReadClientCAFile,
		fixture.options.WriteClientCAFile,
	} {
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatalf("Chmod(%s) error = %v", filepath.Base(path), err)
		}
	}

	verifier, configuration, err := runneridentity.LoadFiles(fixture.options)
	if err != nil || verifier == nil || configuration == nil {
		t.Fatalf("LoadFiles(app-owned mode 0400 staging files) = %#v, %#v, %v", verifier, configuration, err)
	}
}

func TestLoadFilesRejectsUnsafePathsAndFileMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, fixture *fileFixture)
	}{
		{name: "relative path", mutate: func(_ *testing.T, fixture *fileFixture) {
			fixture.options.ServerCertFile = "server-chain.pem"
		}},
		{name: "unclean absolute path", mutate: func(_ *testing.T, fixture *fileFixture) {
			fixture.options.ServerCertFile = filepath.Dir(fixture.options.ServerCertFile) +
				string(os.PathSeparator) + "ignored" + string(os.PathSeparator) + ".." + string(os.PathSeparator) +
				filepath.Base(fixture.options.ServerCertFile)
		}},
		{name: "certificate and key same path", mutate: func(_ *testing.T, fixture *fileFixture) {
			fixture.options.ServerKeyFile = fixture.options.ServerCertFile
		}},
		{name: "symlink", mutate: func(t *testing.T, fixture *fileFixture) {
			t.Helper()
			target := fixture.options.ReadClientCAFile
			link := filepath.Join(filepath.Dir(target), "read-link.pem")
			if err := os.Symlink(target, link); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
			fixture.options.ReadClientCAFile = link
		}},
		{name: "non regular file", mutate: func(t *testing.T, fixture *fileFixture) {
			t.Helper()
			directory := filepath.Join(filepath.Dir(fixture.options.ReadClientCAFile), "ca-directory")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatalf("Mkdir() error = %v", err)
			}
			fixture.options.ReadClientCAFile = directory
		}},
		{name: "empty file", mutate: func(t *testing.T, fixture *fileFixture) {
			writeFixtureFile(t, fixture.options.ReadClientCAFile, nil, 0o644)
		}},
		{name: "oversized file", mutate: func(t *testing.T, fixture *fileFixture) {
			writeFixtureFile(t, fixture.options.ReadClientCAFile, make([]byte, maximumRunnerIdentityFileSize+1), 0o644)
		}},
		{name: "group readable private key", mutate: func(t *testing.T, fixture *fileFixture) {
			if err := os.Chmod(fixture.options.ServerKeyFile, 0o640); err != nil {
				t.Fatalf("Chmod() error = %v", err)
			}
		}},
		{name: "world executable private key", mutate: func(t *testing.T, fixture *fileFixture) {
			if err := os.Chmod(fixture.options.ServerKeyFile, 0o701); err != nil {
				t.Fatalf("Chmod() error = %v", err)
			}
		}},
		{name: "group writable server certificate", mutate: func(t *testing.T, fixture *fileFixture) {
			if err := os.Chmod(fixture.options.ServerCertFile, 0o664); err != nil {
				t.Fatalf("Chmod() error = %v", err)
			}
		}},
		{name: "world writable READ CA", mutate: func(t *testing.T, fixture *fileFixture) {
			if err := os.Chmod(fixture.options.ReadClientCAFile, 0o646); err != nil {
				t.Fatalf("Chmod() error = %v", err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileFixture(t)
			test.mutate(t, &fixture)
			assertFileConfigurationRejected(t, fixture.options)
		})
	}
}

func TestLoadFilesRejectsHardlinkedRoleFiles(t *testing.T) {
	fixture := newFileFixture(t)
	alias := filepath.Join(filepath.Dir(fixture.options.WriteClientCAFile), "write-hardlink.pem")
	if err := os.Remove(fixture.options.WriteClientCAFile); err != nil {
		t.Fatalf("Remove(write CA) error = %v", err)
	}
	if err := os.Link(fixture.options.ReadClientCAFile, alias); err != nil {
		t.Fatalf("Link(READ CA, WRITE CA) error = %v", err)
	}
	fixture.options.WriteClientCAFile = alias

	assertFileConfigurationRejected(t, fixture.options)
}

func TestLoadFilesRejectsFileNotOwnedByEffectiveUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires a privileged test process")
	}
	fixture := newFileFixture(t)
	if err := os.Chown(fixture.options.ReadClientCAFile, 1, -1); err != nil {
		t.Fatalf("Chown(READ CA) error = %v", err)
	}
	assertFileConfigurationRejected(t, fixture.options)
}

func TestLoadFilesRejectsExtendedAttributesAndAccessControlLists(t *testing.T) {
	t.Run("extended attribute", func(t *testing.T) {
		fixture := newFileFixture(t)
		setFixtureExtendedAttribute(t, fixture.options.ReadClientCAFile)
		assertFileConfigurationRejected(t, fixture.options)
	})

	if runtime.GOOS == "darwin" {
		t.Run("macOS extended ACL", func(t *testing.T) {
			fixture := newFileFixture(t)
			command := exec.Command("/bin/chmod", "+a", "everyone allow read", fixture.options.ReadClientCAFile)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("chmod +a error = %v: %s", err, output)
			}
			assertFileConfigurationRejected(t, fixture.options)
		})
	}
}

func TestLoadFilesRejectsMalformedOrUnexpectedPEMWithoutLeakingContents(t *testing.T) {
	const canary = "RUNNER-PRIVATE-MATERIAL-CANARY"
	tests := []struct {
		name   string
		mutate func(t *testing.T, fixture *fileFixture)
	}{
		{name: "malformed server certificate", mutate: func(t *testing.T, fixture *fileFixture) {
			writeFixtureFile(t, fixture.options.ServerCertFile, []byte(canary), 0o644)
		}},
		{name: "server certificate trailing garbage", mutate: func(t *testing.T, fixture *fileFixture) {
			contents := append(certificatePEM(fixture.server.TLS.Certificate...), []byte(canary)...)
			writeFixtureFile(t, fixture.options.ServerCertFile, contents, 0o644)
		}},
		{name: "malformed private key", mutate: func(t *testing.T, fixture *fileFixture) {
			writeFixtureFile(t, fixture.options.ServerKeyFile, []byte(canary), 0o600)
		}},
		{name: "private key has unexpected certificate block", mutate: func(t *testing.T, fixture *fileFixture) {
			contents := append(privateKeyPEM(t, fixture.server.TLS.PrivateKey), certificatePEM(fixture.readCA.Certificate.Raw)...)
			writeFixtureFile(t, fixture.options.ServerKeyFile, contents, 0o600)
		}},
		{name: "private key block has headers", mutate: func(t *testing.T, fixture *fileFixture) {
			keyBlock, _ := pem.Decode(privateKeyPEM(t, fixture.server.TLS.PrivateKey))
			keyBlock.Headers = map[string]string{"Canary": canary}
			writeFixtureFile(t, fixture.options.ServerKeyFile, pem.EncodeToMemory(keyBlock), 0o600)
		}},
		{name: "malformed CA certificate", mutate: func(t *testing.T, fixture *fileFixture) {
			writeFixtureFile(t, fixture.options.ReadClientCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte(canary)}), 0o644)
		}},
		{name: "CA has unexpected block", mutate: func(t *testing.T, fixture *fileFixture) {
			writeFixtureFile(t, fixture.options.ReadClientCAFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte(canary)}), 0o644)
		}},
		{name: "CA block has headers", mutate: func(t *testing.T, fixture *fileFixture) {
			writeFixtureFile(t, fixture.options.ReadClientCAFile, pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Headers: map[string]string{"Canary": canary}, Bytes: fixture.readCA.Certificate.Raw,
			}), 0o644)
		}},
		{name: "CA trailing garbage", mutate: func(t *testing.T, fixture *fileFixture) {
			contents := append(certificatePEM(fixture.readCA.Certificate.Raw), []byte(canary)...)
			writeFixtureFile(t, fixture.options.ReadClientCAFile, contents, 0o644)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileFixture(t)
			test.mutate(t, &fixture)
			_, _, err := runneridentity.LoadFiles(fixture.options)
			if !errors.Is(err, runneridentity.ErrInvalidConfiguration) {
				t.Fatalf("LoadFiles() error = %v, want invalid configuration", err)
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("LoadFiles() leaked file or private-key contents: %v", err)
			}
		})
	}
}

func TestLoadFilesRejectsDuplicateAndOverlappingClientAuthorities(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, fixture *fileFixture)
	}{
		{name: "duplicate certificate in one pool", mutate: func(t *testing.T, fixture *fileFixture) {
			writeFixtureFile(t, fixture.options.ReadClientCAFile, certificatePEM(
				fixture.readCA.Certificate.Raw, fixture.readCA.Certificate.Raw,
			), 0o644)
		}},
		{name: "same certificate across pools", mutate: func(t *testing.T, fixture *fileFixture) {
			writeFixtureFile(t, fixture.options.WriteClientCAFile, certificatePEM(fixture.readCA.Certificate.Raw), 0o644)
		}},
		{name: "same SPKI across pools", mutate: func(t *testing.T, fixture *fileFixture) {
			reissued, err := fixture.readCA.Reissue("runner-write-reissued-root", fixture.now)
			if err != nil {
				t.Fatalf("Authority.Reissue() error = %v", err)
			}
			writeFixtureFile(t, fixture.options.WriteClientCAFile, certificatePEM(reissued.Certificate.Raw), 0o644)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileFixture(t)
			test.mutate(t, &fixture)
			assertFileConfigurationRejected(t, fixture.options)
		})
	}
}

func TestLoadFilesRejectsKeyMismatchDuplicateChainAndNonCurrentServerChain(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, fixture *fileFixture)
	}{
		{name: "key mismatch", mutate: func(t *testing.T, fixture *fileFixture) {
			other, err := fixture.serverCA.IssueServer("other-runner-gateway.test", fixture.now)
			if err != nil {
				t.Fatalf("IssueServer(other) error = %v", err)
			}
			writeFixtureFile(t, fixture.options.ServerKeyFile, privateKeyPEM(t, other.TLS.PrivateKey), 0o600)
		}},
		{name: "duplicate server chain certificate", mutate: func(t *testing.T, fixture *fileFixture) {
			chain := append(append([][]byte(nil), fixture.server.TLS.Certificate...), fixture.server.TLS.Certificate[0])
			writeFixtureFile(t, fixture.options.ServerCertFile, certificatePEM(chain...), 0o644)
		}},
		{name: "server chain expired at configured clock", mutate: func(_ *testing.T, fixture *fileFixture) {
			fixture.options.Clock = func() time.Time { return fixture.now.Add(2 * time.Hour) }
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileFixture(t)
			test.mutate(t, &fixture)
			assertFileConfigurationRejected(t, fixture.options)
		})
	}
}

type fileFixture struct {
	options  runneridentity.FileOptions
	now      time.Time
	readCA   *testpki.Authority
	writeCA  *testpki.Authority
	serverCA *testpki.Authority
	server   testpki.Certificate
}

func newFileFixture(t *testing.T) fileFixture {
	t.Helper()
	now := time.Date(2026, time.July, 11, 12, 0, 0, 0, time.UTC)
	readCA := mustFileAuthority(t, "runner-read-root", now)
	writeCA := mustFileAuthority(t, "runner-write-root", now)
	serverCA := mustFileAuthority(t, "runner-server-root", now)
	server, err := serverCA.IssueServer("runner-gateway.test", now)
	if err != nil {
		t.Fatalf("Authority.IssueServer() error = %v", err)
	}
	directory := t.TempDir()
	options := runneridentity.FileOptions{
		ServerCertFile:    filepath.Join(directory, "server-chain.pem"),
		ServerKeyFile:     filepath.Join(directory, "server-key.pem"),
		ReadClientCAFile:  filepath.Join(directory, "read-client-roots.pem"),
		WriteClientCAFile: filepath.Join(directory, "write-client-roots.pem"),
		TrustDomain:       "aiops.example", Clock: func() time.Time { return now },
	}
	writeFixtureFile(t, options.ServerCertFile, certificatePEM(server.TLS.Certificate...), 0o644)
	writeFixtureFile(t, options.ServerKeyFile, privateKeyPEM(t, server.TLS.PrivateKey), 0o600)
	writeFixtureFile(t, options.ReadClientCAFile, certificatePEM(readCA.Certificate.Raw), 0o644)
	writeFixtureFile(t, options.WriteClientCAFile, certificatePEM(writeCA.Certificate.Raw), 0o644)
	return fileFixture{
		options: options, now: now, readCA: readCA, writeCA: writeCA, serverCA: serverCA, server: server,
	}
}

func assertFileConfigurationRejected(t *testing.T, options runneridentity.FileOptions) {
	t.Helper()
	verifier, configuration, err := runneridentity.LoadFiles(options)
	if !errors.Is(err, runneridentity.ErrInvalidConfiguration) || verifier != nil || configuration != nil {
		t.Fatalf("LoadFiles() = %#v, %#v, %v; want invalid configuration", verifier, configuration, err)
	}
}

func writeFixtureFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", filepath.Base(path), err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod(%s) error = %v", filepath.Base(path), err)
	}
}

func setFixtureExtendedAttribute(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(xattr fixture) error = %v", err)
	}
	defer file.Close()
	name, err := syscall.BytePtrFromString("user.aiops-runner-identity-test")
	if err != nil {
		t.Fatalf("BytePtrFromString(xattr) error = %v", err)
	}
	value := []byte("present")
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FSETXATTR,
		file.Fd(),
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&value[0])),
		uintptr(len(value)),
		0,
		0,
	)
	runtime.KeepAlive(name)
	runtime.KeepAlive(value)
	if errno != 0 {
		t.Fatalf("fsetxattr() error = %v", errno)
	}
}

func certificatePEM(certificates ...[]byte) []byte {
	var contents []byte
	for _, certificate := range certificates {
		contents = append(contents, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})...)
	}
	return contents
}

func privateKeyPEM(t *testing.T, privateKey any) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

func mustFileAuthority(t *testing.T, name string, now time.Time) *testpki.Authority {
	t.Helper()
	authority, err := testpki.NewAuthority(name, now)
	if err != nil {
		t.Fatalf("testpki.NewAuthority(%q) error = %v", name, err)
	}
	return authority
}
