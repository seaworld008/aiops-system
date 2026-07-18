package main

import (
	"errors"
	"flag"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

var errConfigUnavailable = errors.New("discovery worker configuration rejected")

type Config struct {
	DatabaseDSNFile              string
	WorkloadCertificateFile      string
	WorkloadPrivateKeyFile       string
	WorkloadCAFile               string
	SourceProfileManifestFile    string
	SourceProfileManifestKeyFile string
	SessionAuthorityEndpoint     string
	SessionAuthorityServerName   string
	SessionAuthorityPeerIdentity string
	CheckpointKeyringFile        string
	CleanupProofKeyFile          string
	MetricsBindAddress           string
}

type configBinding struct {
	Flag        string
	Environment string
}

var configBindings = []configBinding{
	{Flag: "database-dsn-file", Environment: "AIOPS_DISCOVERY_DATABASE_DSN_FILE"},
	{Flag: "workload-certificate-file", Environment: "AIOPS_DISCOVERY_WORKLOAD_CERTIFICATE_FILE"},
	{Flag: "workload-private-key-file", Environment: "AIOPS_DISCOVERY_WORKLOAD_PRIVATE_KEY_FILE"},
	{Flag: "workload-ca-file", Environment: "AIOPS_DISCOVERY_WORKLOAD_CA_FILE"},
	{Flag: "source-profile-manifest-file", Environment: "AIOPS_DISCOVERY_SOURCE_PROFILE_MANIFEST_FILE"},
	{Flag: "source-profile-manifest-key-file", Environment: "AIOPS_DISCOVERY_SOURCE_PROFILE_MANIFEST_KEY_FILE"},
	{Flag: "session-authority-endpoint", Environment: "AIOPS_DISCOVERY_SESSION_AUTHORITY_ENDPOINT"},
	{Flag: "session-authority-server-name", Environment: "AIOPS_DISCOVERY_SESSION_AUTHORITY_SERVER_NAME"},
	{Flag: "session-authority-peer-identity", Environment: "AIOPS_DISCOVERY_SESSION_AUTHORITY_PEER_IDENTITY"},
	{Flag: "checkpoint-keyring-file", Environment: "AIOPS_DISCOVERY_CHECKPOINT_KEYRING_FILE"},
	{Flag: "cleanup-proof-key-file", Environment: "AIOPS_DISCOVERY_CLEANUP_PROOF_KEY_FILE"},
	{Flag: "metrics-bind", Environment: "AIOPS_DISCOVERY_METRICS_BIND"},
}

func loadConfig(arguments, environment []string) (Config, error) {
	knownEnvironment := make(map[string]configBinding, len(configBindings))
	for _, binding := range configBindings {
		knownEnvironment[binding.Environment] = binding
	}
	environmentValues := make(map[string]string, len(configBindings))
	seenEnvironment := make(map[string]struct{}, len(environment))
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found || name == "" {
			return Config{}, errConfigUnavailable
		}
		if _, duplicate := seenEnvironment[name]; duplicate {
			return Config{}, errConfigUnavailable
		}
		seenEnvironment[name] = struct{}{}
		binding, known := knownEnvironment[name]
		if !known {
			if strings.HasPrefix(name, "AIOPS_DISCOVERY_") {
				return Config{}, errConfigUnavailable
			}
			continue
		}
		environmentValues[binding.Flag] = value
	}

	flagValues := make(map[string]string, len(configBindings))
	flags := flag.NewFlagSet("discovery-worker", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	for _, binding := range configBindings {
		binding := binding
		flags.Func(binding.Flag, "", func(value string) error {
			if _, duplicate := flagValues[binding.Flag]; duplicate {
				return errConfigUnavailable
			}
			flagValues[binding.Flag] = value
			return nil
		})
	}
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return Config{}, errConfigUnavailable
	}

	var config Config
	for _, binding := range configBindings {
		fromEnvironment, environmentSet := environmentValues[binding.Flag]
		fromFlag, flagSet := flagValues[binding.Flag]
		if environmentSet && flagSet {
			return Config{}, errConfigUnavailable
		}
		value := fromEnvironment
		if flagSet {
			value = fromFlag
		}
		setConfigValue(&config, binding.Flag, value)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func setConfigValue(config *Config, flagName, value string) {
	switch flagName {
	case "database-dsn-file":
		config.DatabaseDSNFile = value
	case "workload-certificate-file":
		config.WorkloadCertificateFile = value
	case "workload-private-key-file":
		config.WorkloadPrivateKeyFile = value
	case "workload-ca-file":
		config.WorkloadCAFile = value
	case "source-profile-manifest-file":
		config.SourceProfileManifestFile = value
	case "source-profile-manifest-key-file":
		config.SourceProfileManifestKeyFile = value
	case "session-authority-endpoint":
		config.SessionAuthorityEndpoint = value
	case "session-authority-server-name":
		config.SessionAuthorityServerName = value
	case "session-authority-peer-identity":
		config.SessionAuthorityPeerIdentity = value
	case "checkpoint-keyring-file":
		config.CheckpointKeyringFile = value
	case "cleanup-proof-key-file":
		config.CleanupProofKeyFile = value
	case "metrics-bind":
		config.MetricsBindAddress = value
	}
}

func (config Config) Validate() error {
	paths := []string{
		config.DatabaseDSNFile,
		config.WorkloadCertificateFile,
		config.WorkloadPrivateKeyFile,
		config.WorkloadCAFile,
		config.SourceProfileManifestFile,
		config.SourceProfileManifestKeyFile,
		config.CheckpointKeyringFile,
		config.CleanupProofKeyFile,
	}
	seenPaths := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if !validConfigPath(path) {
			return errConfigUnavailable
		}
		if _, duplicate := seenPaths[path]; duplicate {
			return errConfigUnavailable
		}
		seenPaths[path] = struct{}{}
	}
	if !validSessionAuthorityEndpoint(config.SessionAuthorityEndpoint) ||
		!validServerName(config.SessionAuthorityServerName) ||
		!validSPIFFEIdentity(config.SessionAuthorityPeerIdentity) ||
		!validMetricsBind(config.MetricsBindAddress) {
		return errConfigUnavailable
	}
	return nil
}

func validConfigPath(path string) bool {
	return path != "" && len(path) <= 4096 && filepath.IsAbs(path) &&
		filepath.Clean(path) == path && strings.TrimSpace(path) == path &&
		!containsControl(path)
}

func validSessionAuthorityEndpoint(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil ||
		parsed.Host == "" || parsed.Hostname() == "" || parsed.Port() == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" ||
		parsed.Fragment != "" || containsControl(value) {
		return false
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	return err == nil && port != 0 && parsed.String() == value
}

func validServerName(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value ||
		containsControl(value) || net.ParseIP(value) != nil ||
		strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' ||
			label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validSPIFFEIdentity(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "spiffe" && parsed.Host != "" &&
		parsed.User == nil && parsed.Port() == "" && parsed.Opaque == "" &&
		parsed.Path != "" && parsed.Path != "/" && parsed.RawPath == "" &&
		parsed.RawQuery == "" && parsed.Fragment == "" &&
		!strings.Contains(parsed.Path, "//") && !containsControl(value) &&
		parsed.String() == value
}

func validMetricsBind(value string) bool {
	host, portValue, err := net.SplitHostPort(value)
	if err != nil || host == "" || portValue == "" || containsControl(value) {
		return false
	}
	address := net.ParseIP(host)
	port, portErr := strconv.ParseUint(portValue, 10, 16)
	return portErr == nil && port != 0 && address != nil && address.IsLoopback()
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
