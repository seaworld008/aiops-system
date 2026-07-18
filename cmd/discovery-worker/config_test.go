package main

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestConfigFlagsAndEnvironmentAreExactAndContainNoIdentityInjection(t *testing.T) {
	wantFlags := []string{
		"checkpoint-keyring-file",
		"cleanup-proof-key-file",
		"database-dsn-file",
		"metrics-bind",
		"session-authority-endpoint",
		"session-authority-peer-identity",
		"session-authority-server-name",
		"source-profile-manifest-file",
		"source-profile-manifest-key-file",
		"workload-ca-file",
		"workload-certificate-file",
		"workload-private-key-file",
	}
	wantEnvironment := []string{
		"AIOPS_DISCOVERY_CHECKPOINT_KEYRING_FILE",
		"AIOPS_DISCOVERY_CLEANUP_PROOF_KEY_FILE",
		"AIOPS_DISCOVERY_DATABASE_DSN_FILE",
		"AIOPS_DISCOVERY_METRICS_BIND",
		"AIOPS_DISCOVERY_SESSION_AUTHORITY_ENDPOINT",
		"AIOPS_DISCOVERY_SESSION_AUTHORITY_PEER_IDENTITY",
		"AIOPS_DISCOVERY_SESSION_AUTHORITY_SERVER_NAME",
		"AIOPS_DISCOVERY_SOURCE_PROFILE_MANIFEST_FILE",
		"AIOPS_DISCOVERY_SOURCE_PROFILE_MANIFEST_KEY_FILE",
		"AIOPS_DISCOVERY_WORKLOAD_CA_FILE",
		"AIOPS_DISCOVERY_WORKLOAD_CERTIFICATE_FILE",
		"AIOPS_DISCOVERY_WORKLOAD_PRIVATE_KEY_FILE",
	}
	var gotFlags, gotEnvironment []string
	for _, binding := range configBindings {
		gotFlags = append(gotFlags, binding.Flag)
		gotEnvironment = append(gotEnvironment, binding.Environment)
	}
	slices.Sort(gotFlags)
	slices.Sort(gotEnvironment)
	if !reflect.DeepEqual(gotFlags, wantFlags) {
		t.Fatalf("config flags = %#v", gotFlags)
	}
	if !reflect.DeepEqual(gotEnvironment, wantEnvironment) {
		t.Fatalf("config environment = %#v", gotEnvironment)
	}

	configType := reflect.TypeOf(Config{})
	for index := 0; index < configType.NumField(); index++ {
		name := strings.ToLower(configType.Field(index).Name)
		for _, forbidden := range []string{
			"workerid", "workeridentity", "processid", "processidentity",
			"workerdigest", "processdigest", "bootid", "hostname",
		} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("Config exposes identity injection field %q", configType.Field(index).Name)
			}
		}
	}
	for _, binding := range configBindings {
		joined := strings.ToLower(binding.Flag + " " + binding.Environment)
		for _, forbidden := range []string{
			"worker-id", "worker_identity", "process-id", "process_identity",
			"worker-digest", "process_digest", "boot-id", "hostname",
		} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("config binding exposes identity alias %q: %#v", forbidden, binding)
			}
		}
	}
}

func TestLoadConfigAcceptsOnlyTheFixedClosedSurface(t *testing.T) {
	environment := validConfigEnvironment()
	config, err := loadConfig(nil, environment)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("Config.Validate() error = %v", err)
	}

	flagConfig, err := loadConfig([]string{
		"--database-dsn-file=/secure/db",
		"--workload-certificate-file=/secure/cert",
		"--workload-private-key-file=/secure/key",
		"--workload-ca-file=/secure/ca",
		"--source-profile-manifest-file=/secure/profile",
		"--source-profile-manifest-key-file=/secure/profile-key",
		"--session-authority-endpoint=https://authority.test:8443",
		"--session-authority-server-name=authority.test",
		"--session-authority-peer-identity=spiffe://aiops.test/discovery-session-authority/main",
		"--checkpoint-keyring-file=/secure/checkpoints",
		"--cleanup-proof-key-file=/secure/cleanup",
		"--metrics-bind=127.0.0.1:9464",
	}, nil)
	if err != nil || flagConfig != config {
		t.Fatalf("flag config = %#v,%v, want %#v", flagConfig, err, config)
	}

	for _, forbidden := range [][]string{
		{"--worker-id=forged"},
		{"--worker-identity-digest=" + strings.Repeat("a", 64)},
		{"--process-id=forged"},
		{"--process-instance-digest=" + strings.Repeat("b", 64)},
		{"--session-opener=forged"},
		{"--runtime-resolver=forged"},
	} {
		if _, err := loadConfig(forbidden, nil); err == nil {
			t.Fatalf("loadConfig(%q) accepted forbidden alias", forbidden)
		}
	}
	for _, forbidden := range []string{
		"AIOPS_DISCOVERY_WORKER_ID=forged",
		"AIOPS_DISCOVERY_WORKER_IDENTITY_DIGEST=" + strings.Repeat("a", 64),
		"AIOPS_DISCOVERY_PROCESS_ID=forged",
		"AIOPS_DISCOVERY_PROCESS_INSTANCE_DIGEST=" + strings.Repeat("b", 64),
		"AIOPS_DISCOVERY_SESSION_OPENER=forged",
		"AIOPS_DISCOVERY_RUNTIME_RESOLVER=forged",
	} {
		candidate := append(slices.Clone(environment), forbidden)
		if _, err := loadConfig(nil, candidate); err == nil {
			t.Fatalf("loadConfig() accepted forbidden environment %q", forbidden)
		}
	}
}

func TestConfigRejectsEveryMissingOrStructurallyUnsafeValue(t *testing.T) {
	valid, err := loadConfig(nil, validConfigEnvironment())
	if err != nil {
		t.Fatalf("load valid config: %v", err)
	}
	tests := map[string]func(*Config){
		"database":             func(value *Config) { value.DatabaseDSNFile = "" },
		"workload certificate": func(value *Config) { value.WorkloadCertificateFile = "" },
		"workload key":         func(value *Config) { value.WorkloadPrivateKeyFile = "" },
		"workload ca":          func(value *Config) { value.WorkloadCAFile = "" },
		"profile manifest":     func(value *Config) { value.SourceProfileManifestFile = "" },
		"profile key":          func(value *Config) { value.SourceProfileManifestKeyFile = "" },
		"authority endpoint":   func(value *Config) { value.SessionAuthorityEndpoint = "" },
		"authority server":     func(value *Config) { value.SessionAuthorityServerName = "" },
		"authority identity":   func(value *Config) { value.SessionAuthorityPeerIdentity = "" },
		"checkpoint keyring":   func(value *Config) { value.CheckpointKeyringFile = "" },
		"cleanup proof key":    func(value *Config) { value.CleanupProofKeyFile = "" },
		"metrics bind":         func(value *Config) { value.MetricsBindAddress = "" },
		"relative secret":      func(value *Config) { value.WorkloadPrivateKeyFile = "relative/key" },
		"unclean path":         func(value *Config) { value.DatabaseDSNFile = "/secure/../db" },
		"public metrics":       func(value *Config) { value.MetricsBindAddress = "0.0.0.0:9464" },
		"hostname metrics":     func(value *Config) { value.MetricsBindAddress = "localhost:9464" },
		"dynamic metrics port": func(value *Config) { value.MetricsBindAddress = "127.0.0.1:0" },
		"authority userinfo": func(value *Config) {
			value.SessionAuthorityEndpoint = "https://user@authority.test:8443"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatalf("Config.Validate() accepted %#v", candidate)
			}
		})
	}
}

func validConfigEnvironment() []string {
	return []string{
		"AIOPS_DISCOVERY_DATABASE_DSN_FILE=/secure/db",
		"AIOPS_DISCOVERY_WORKLOAD_CERTIFICATE_FILE=/secure/cert",
		"AIOPS_DISCOVERY_WORKLOAD_PRIVATE_KEY_FILE=/secure/key",
		"AIOPS_DISCOVERY_WORKLOAD_CA_FILE=/secure/ca",
		"AIOPS_DISCOVERY_SOURCE_PROFILE_MANIFEST_FILE=/secure/profile",
		"AIOPS_DISCOVERY_SOURCE_PROFILE_MANIFEST_KEY_FILE=/secure/profile-key",
		"AIOPS_DISCOVERY_SESSION_AUTHORITY_ENDPOINT=https://authority.test:8443",
		"AIOPS_DISCOVERY_SESSION_AUTHORITY_SERVER_NAME=authority.test",
		"AIOPS_DISCOVERY_SESSION_AUTHORITY_PEER_IDENTITY=spiffe://aiops.test/discovery-session-authority/main",
		"AIOPS_DISCOVERY_CHECKPOINT_KEYRING_FILE=/secure/checkpoints",
		"AIOPS_DISCOVERY_CLEANUP_PROOF_KEY_FILE=/secure/cleanup",
		"AIOPS_DISCOVERY_METRICS_BIND=127.0.0.1:9464",
	}
}
