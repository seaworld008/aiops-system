package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/config"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

func TestNewRunnerGatewayRuntimeBuildsPinnedDisabledBoundary(t *testing.T) {
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	configuration := runnerGatewayFixture(t)

	runtime, err := newRunnerGatewayRuntime(configuration, config.WriteExecutionModeDisabled, database)
	if err != nil {
		t.Fatalf("newRunnerGatewayRuntime() error = %v", err)
	}
	if runtime == nil || runtime.server == nil || runtime.protector == nil {
		t.Fatalf("newRunnerGatewayRuntime() = %#v", runtime)
	}
	runtime.Destroy()
	if runtime.protector != nil {
		t.Fatal("Destroy() retained credential protector")
	}
}

func TestNewRunnerGatewayRuntimeRejectsKeyringFailureWithoutLeakingContents(t *testing.T) {
	const canary = "CONTROL-PLANE-KEYRING-CANARY"
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	configuration := runnerGatewayFixture(t)
	if err := os.Chmod(configuration.CredentialKeyringFile, 0o600); err != nil {
		t.Fatalf("Chmod(keyring) error = %v", err)
	}
	writeControlPlaneFixture(t, configuration.CredentialKeyringFile, []byte(canary), 0o400)

	runtime, err := newRunnerGatewayRuntime(configuration, config.WriteExecutionModeDisabled, database)
	if err == nil || runtime != nil {
		t.Fatalf("newRunnerGatewayRuntime(invalid keyring) = %#v, %v", runtime, err)
	}
	if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), configuration.CredentialKeyringFile) {
		t.Fatalf("newRunnerGatewayRuntime() leaked private input: %v", err)
	}
}

func TestNewRunnerGatewayRuntimeTreatsAbsentConfigurationAsDisabled(t *testing.T) {
	runtime, err := newRunnerGatewayRuntime(nil, config.WriteExecutionModeDisabled, nil)
	if err != nil || runtime != nil {
		t.Fatalf("newRunnerGatewayRuntime(nil) = %#v, %v", runtime, err)
	}
}

func runnerGatewayFixture(t *testing.T) *config.RunnerGatewayConfig {
	t.Helper()
	now := time.Now().UTC()
	readAuthority := mustControlPlaneAuthority(t, "runner-read-root", now)
	writeAuthority := mustControlPlaneAuthority(t, "runner-write-root", now)
	serverAuthority := mustControlPlaneAuthority(t, "runner-server-root", now)
	serverCertificate, err := serverAuthority.IssueServer("runner-gateway.test", now)
	if err != nil {
		t.Fatalf("IssueServer() error = %v", err)
	}
	directory := t.TempDir()
	configuration := &config.RunnerGatewayConfig{
		Addr: ":8443", TrustDomain: "aiops.example",
		ServerCertFile:        filepath.Join(directory, "server-chain.pem"),
		ServerKeyFile:         filepath.Join(directory, "server-key.pem"),
		ReadClientCAFile:      filepath.Join(directory, "read-client-roots.pem"),
		WriteClientCAFile:     filepath.Join(directory, "write-client-roots.pem"),
		CredentialKeyringFile: filepath.Join(directory, "credential-keyring.json"),
	}
	writeControlPlaneFixture(t, configuration.ServerCertFile,
		controlPlaneCertificatePEM(serverCertificate.TLS.Certificate...), 0o400)
	writeControlPlaneFixture(t, configuration.ServerKeyFile,
		controlPlanePrivateKeyPEM(t, serverCertificate.TLS.PrivateKey), 0o400)
	writeControlPlaneFixture(t, configuration.ReadClientCAFile,
		controlPlaneCertificatePEM(readAuthority.Certificate.Raw), 0o400)
	writeControlPlaneFixture(t, configuration.WriteClientCAFile,
		controlPlaneCertificatePEM(writeAuthority.Certificate.Raw), 0o400)
	writeControlPlaneFixture(t, configuration.CredentialKeyringFile, []byte(controlPlaneKeyringJSON()), 0o400)
	return configuration
}

func writeControlPlaneFixture(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", filepath.Base(path), err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod(%s) error = %v", filepath.Base(path), err)
	}
}

func controlPlaneCertificatePEM(certificates ...[]byte) []byte {
	var contents []byte
	for _, certificate := range certificates {
		contents = append(contents, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})...)
	}
	return contents
}

func controlPlanePrivateKeyPEM(t *testing.T, privateKey any) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	defer clear(encoded)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

func mustControlPlaneAuthority(t *testing.T, name string, now time.Time) *testpki.Authority {
	t.Helper()
	authority, err := testpki.NewAuthority(name, now)
	if err != nil {
		t.Fatalf("NewAuthority(%q) error = %v", name, err)
	}
	return authority
}

func controlPlaneKeyringJSON() string {
	encryptionKey := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("e", 32)))
	hmacKey := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("h", 32)))
	return `{"schema_version":"credential-protection-keyring.v1","active_key_id":"key-1","keys":[` +
		`{"id":"key-1","encryption_key_b64u":"` + encryptionKey + `","hmac_key_b64u":"` + hmacKey + `"}]}`
}
