package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const recoveryPostgreSQLImage = "postgres:18.4-alpine3.24@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"

type recoveryDocker struct {
	contextName string
}

type recoveryPostgreSQLContainer struct {
	docker       recoveryDocker
	name         string
	username     string
	password     string
	databaseName string
	hostPort     uint16
}

type recoveryPostgreSQLPair struct {
	source       *recoveryPostgreSQLContainer
	target       *recoveryPostgreSQLContainer
	sourcePool   *pgxpool.Pool
	targetPool   *pgxpool.Pool
	sourceSystem string
	targetSystem string
}

func prepareRecoveryPostgreSQLPair(t *testing.T) *recoveryPostgreSQLPair {
	t.Helper()
	required := strings.TrimSpace(os.Getenv("AIOPS_TEST_POSTGRES_DSN")) != ""
	docker, err := discoverRecoveryDocker()
	if err != nil {
		rejectRecoveryPrerequisite(t, required, err)
		return nil
	}
	if err := docker.ensureRecoveryImage(); err != nil {
		rejectRecoveryPrerequisite(t, required, err)
		return nil
	}

	source, err := startRecoveryPostgreSQLContainer(t, docker, "source")
	if err != nil {
		rejectRecoveryPrerequisite(t, required, err)
		return nil
	}
	target, err := startRecoveryPostgreSQLContainer(t, docker, "target")
	if err != nil {
		rejectRecoveryPrerequisite(t, required, err)
		return nil
	}

	sourcePool, sourceSystem, err := connectAndInspectRecoveryPostgreSQL(source)
	if err != nil {
		rejectRecoveryPrerequisite(t, required, err)
		return nil
	}
	t.Cleanup(sourcePool.Close)
	targetPool, targetSystem, err := connectAndInspectRecoveryPostgreSQL(target)
	if err != nil {
		rejectRecoveryPrerequisite(t, required, err)
		return nil
	}
	t.Cleanup(targetPool.Close)
	if sourceSystem == targetSystem {
		t.Fatalf("recovery source and target have the same PostgreSQL system_identifier")
	}

	return &recoveryPostgreSQLPair{
		source:       source,
		target:       target,
		sourcePool:   sourcePool,
		targetPool:   targetPool,
		sourceSystem: sourceSystem,
		targetSystem: targetSystem,
	}
}

func rejectRecoveryPrerequisite(t *testing.T, required bool, err error) {
	t.Helper()
	if required {
		t.Fatalf("PostgreSQL recovery prerequisite failed while AIOPS_TEST_POSTGRES_DSN is configured: %v", err)
	}
	t.Skipf("PostgreSQL recovery prerequisite is unavailable: %v", err)
}

func discoverRecoveryDocker() (recoveryDocker, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return recoveryDocker{}, errors.New("docker CLI was not found")
	}
	if name := strings.TrimSpace(os.Getenv("AIOPS_TEST_DOCKER_CONTEXT")); name != "" {
		return usableRecoveryDockerContext(name, "AIOPS_TEST_DOCKER_CONTEXT")
	}
	if name := strings.TrimSpace(os.Getenv("DOCKER_CONTEXT")); name != "" {
		return usableRecoveryDockerContext(name, "DOCKER_CONTEXT")
	}
	if host := strings.TrimSpace(os.Getenv("DOCKER_HOST")); host != "" {
		if err := requireLocalUnixDockerEndpoint(host); err != nil {
			return recoveryDocker{}, fmt.Errorf("DOCKER_HOST is not an allowed local Unix endpoint: %w", err)
		}
		docker := recoveryDocker{}
		if err := docker.probe(); err != nil {
			return recoveryDocker{}, fmt.Errorf("DOCKER_HOST local daemon is unreachable: %w", err)
		}
		return docker, nil
	}

	current, currentErr := currentRecoveryDockerContext()
	if currentErr == nil {
		return current, nil
	}
	if errors.Is(currentErr, errRemoteDockerEndpoint) {
		return recoveryDocker{}, currentErr
	}

	contexts, err := localReachableRecoveryDockerContexts()
	if err != nil {
		return recoveryDocker{}, err
	}
	switch len(contexts) {
	case 0:
		return recoveryDocker{}, fmt.Errorf("no reachable local Unix Docker context; current context: %w", currentErr)
	case 1:
		return contexts[0], nil
	default:
		names := make([]string, 0, len(contexts))
		for _, candidate := range contexts {
			names = append(names, candidate.contextName)
		}
		sort.Strings(names)
		return recoveryDocker{}, fmt.Errorf("ambiguous reachable local Unix Docker contexts: %s", strings.Join(names, ", "))
	}
}

var errRemoteDockerEndpoint = errors.New("remote Docker endpoint is forbidden for recovery tests")

func TestRecoveryDockerEndpointPolicy(t *testing.T) {
	for _, endpoint := range []string{"unix:///var/run/docker.sock", "unix:/var/run/docker.sock"} {
		if err := requireLocalUnixDockerEndpoint(endpoint); err != nil {
			t.Errorf("local endpoint %q rejected: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{
		"tcp://127.0.0.1:2375",
		"ssh://operator@example.invalid",
		"npipe:////./pipe/docker_engine",
		"unix://relative/docker.sock",
		"/var/run/docker.sock",
	} {
		if err := requireLocalUnixDockerEndpoint(endpoint); !errors.Is(err, errRemoteDockerEndpoint) {
			t.Errorf("non-local-Unix endpoint %q error=%v, want remote-endpoint rejection", endpoint, err)
		}
	}
}

func TestRecoveryDockerContextOverridesRoutingEnvironment(t *testing.T) {
	filtered := withoutDockerRoutingEnvironment([]string{
		"PATH=/usr/bin",
		"DOCKER_CONTEXT=remote",
		"DOCKER_HOST=tcp://example.invalid:2375",
		"DOCKER_TLS_VERIFY=1",
		"DOCKER_CERT_PATH=/tmp/certs",
		"DOCKER_CONFIG=/tmp/docker-config",
	})
	joined := strings.Join(filtered, "\n")
	if joined != "PATH=/usr/bin\nDOCKER_CONFIG=/tmp/docker-config" {
		t.Fatalf("filtered Docker environment=%q", joined)
	}
}

func usableRecoveryDockerContext(name, source string) (recoveryDocker, error) {
	endpoint, err := inspectRecoveryDockerContextEndpoint(name)
	if err != nil {
		return recoveryDocker{}, fmt.Errorf("inspect Docker context selected by %s: %w", source, err)
	}
	if err := requireLocalUnixDockerEndpoint(endpoint); err != nil {
		return recoveryDocker{}, fmt.Errorf("Docker context %q selected by %s is not allowed: %w", name, source, err)
	}
	docker := recoveryDocker{contextName: name}
	if err := docker.probe(); err != nil {
		return recoveryDocker{}, fmt.Errorf("Docker context %q selected by %s is unreachable: %w", name, source, err)
	}
	return docker, nil
}

func currentRecoveryDockerContext() (recoveryDocker, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", "context", "show").CombinedOutput()
	if err != nil {
		return recoveryDocker{}, fmt.Errorf("read current Docker context: %w: %s", err, sanitizeToolOutput(output))
	}
	name := strings.TrimSpace(string(output))
	if name == "" {
		return recoveryDocker{}, errors.New("current Docker context name is empty")
	}
	endpoint, err := inspectRecoveryDockerContextEndpoint(name)
	if err != nil {
		return recoveryDocker{}, fmt.Errorf("inspect current Docker context %q: %w", name, err)
	}
	if err := requireLocalUnixDockerEndpoint(endpoint); err != nil {
		return recoveryDocker{}, fmt.Errorf("current Docker context %q is forbidden: %w", name, err)
	}
	docker := recoveryDocker{contextName: name}
	if err := docker.probe(); err != nil {
		return recoveryDocker{}, fmt.Errorf("current Docker context %q is unreachable: %w", name, err)
	}
	return docker, nil
}

func localReachableRecoveryDockerContexts() ([]recoveryDocker, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", "context", "ls", "--format", "{{.Name}}").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list Docker contexts: %w: %s", err, sanitizeToolOutput(output))
	}
	seen := make(map[string]struct{})
	var candidates []recoveryDocker
	for _, line := range strings.Split(string(output), "\n") {
		name := strings.TrimSpace(strings.TrimSuffix(line, "*"))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		endpoint, inspectErr := inspectRecoveryDockerContextEndpoint(name)
		if inspectErr != nil || requireLocalUnixDockerEndpoint(endpoint) != nil {
			continue
		}
		docker := recoveryDocker{contextName: name}
		if docker.probe() == nil {
			candidates = append(candidates, docker)
		}
	}
	return candidates, nil
}

func inspectRecoveryDockerContextEndpoint(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", "context", "inspect", name, "--format", "{{(index .Endpoints \"docker\").Host}}")
	command.Env = withoutDockerRoutingEnvironment(os.Environ())
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker context inspect failed: %w: %s", err, sanitizeToolOutput(output))
	}
	endpoint := strings.TrimSpace(string(output))
	if endpoint == "" {
		return "", errors.New("Docker context endpoint is empty")
	}
	return endpoint, nil
}

func requireLocalUnixDockerEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return errRemoteDockerEndpoint
	}
	if parsed.Scheme != "unix" || parsed.Host != "" || !filepath.IsAbs(parsed.Path) {
		return errRemoteDockerEndpoint
	}
	return nil
}

func (docker recoveryDocker) command(ctx context.Context, args ...string) *exec.Cmd {
	commandArgs := make([]string, 0, len(args)+2)
	if docker.contextName != "" {
		commandArgs = append(commandArgs, "--context", docker.contextName)
	}
	commandArgs = append(commandArgs, args...)
	command := exec.CommandContext(ctx, "docker", commandArgs...)
	if docker.contextName != "" {
		command.Env = withoutDockerRoutingEnvironment(os.Environ())
	}
	return command
}

func withoutDockerRoutingEnvironment(environment []string) []string {
	filtered := make([]string, 0, len(environment))
	for _, value := range environment {
		name, _, _ := strings.Cut(value, "=")
		switch name {
		case "DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH":
			continue
		default:
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func (docker recoveryDocker) probe() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := docker.command(ctx, "version", "--format", "{{.Server.Version}}").CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker daemon probe failed: %w: %s", err, sanitizeToolOutput(output))
	}
	if strings.TrimSpace(string(output)) == "" {
		return errors.New("docker daemon returned an empty server version")
	}
	return nil
}

func (docker recoveryDocker) ensureRecoveryImage() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	output, err := docker.command(ctx, "image", "inspect", recoveryPostgreSQLImage, "--format", "{{.Id}}").CombinedOutput()
	cancel()
	if err == nil && strings.TrimSpace(string(output)) != "" {
		return nil
	}
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	output, err = docker.command(ctx, "pull", recoveryPostgreSQLImage).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pull digest-pinned PostgreSQL recovery image: %w: %s", err, sanitizeToolOutput(output))
	}
	return nil
}

func startRecoveryPostgreSQLContainer(
	t *testing.T,
	docker recoveryDocker,
	role string,
) (*recoveryPostgreSQLContainer, error) {
	t.Helper()
	suffix := randomAssetHex(t, 8)
	container := &recoveryPostgreSQLContainer{
		docker:       docker,
		name:         "aiops-assets-recovery-" + role + "-" + suffix,
		username:     "aiops_" + randomAssetHex(t, 6),
		password:     randomAssetHex(t, 24),
		databaseName: "assets_" + randomAssetHex(t, 6),
	}
	envFile := filepath.Join(t.TempDir(), role+".env")
	envContent := strings.Join([]string{
		"POSTGRES_USER=" + container.username,
		"POSTGRES_PASSWORD=" + container.password,
		"POSTGRES_DB=" + container.databaseName,
		"POSTGRES_INITDB_ARGS=--data-checksums",
		"",
	}, "\n")
	if err := os.WriteFile(envFile, []byte(envContent), 0o600); err != nil {
		return nil, fmt.Errorf("create private PostgreSQL environment file: %w", err)
	}
	// Register cleanup before docker run so a daemon-side create followed by a
	// client timeout cannot leave an untracked test container behind.
	t.Cleanup(func() { container.remove(t) })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	output, err := docker.command(ctx,
		"run", "--detach", "--rm",
		"--name", container.name,
		"--label", "aiops.test=asset-catalog-recovery",
		"--env-file", envFile,
		"--publish", "127.0.0.1::5432",
		recoveryPostgreSQLImage,
	).CombinedOutput()
	cancel()
	if err != nil {
		return nil, fmt.Errorf("start isolated PostgreSQL %s container: %w: %s", role, err, sanitizeToolOutput(output))
	}

	if err := container.assertPinnedImage(); err != nil {
		return container, err
	}
	port, err := container.publishedPort()
	if err != nil {
		return container, err
	}
	container.hostPort = port
	if err := container.waitUntilReady(); err != nil {
		return container, err
	}
	if err := container.assertToolVersions(); err != nil {
		return container, err
	}
	return container, nil
}

func (container *recoveryPostgreSQLContainer) assertPinnedImage() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := container.docker.command(ctx, "inspect", container.name, "--format", "{{.Config.Image}}").CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect isolated PostgreSQL container image: %w: %s", err, sanitizeToolOutput(output))
	}
	if strings.TrimSpace(string(output)) != recoveryPostgreSQLImage {
		return errors.New("isolated PostgreSQL container is not using the required digest-pinned image")
	}
	return nil
}

func (container *recoveryPostgreSQLContainer) publishedPort() (uint16, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := container.docker.command(ctx, "port", container.name, "5432/tcp").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("read isolated PostgreSQL published port: %w: %s", err, sanitizeToolOutput(output))
	}
	line := strings.TrimSpace(strings.Split(string(output), "\n")[0])
	host, portText, err := net.SplitHostPort(line)
	if err != nil || host != "127.0.0.1" {
		return 0, fmt.Errorf("isolated PostgreSQL port is not bound to 127.0.0.1")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, errors.New("isolated PostgreSQL published port is invalid")
	}
	return uint16(port), nil
}

func (container *recoveryPostgreSQLContainer) waitUntilReady() error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := container.docker.command(ctx,
			"exec", container.name, "pg_isready", "--quiet",
			"--username", container.username, "--dbname", container.databaseName,
		).Run()
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("isolated PostgreSQL container did not become ready within 60 seconds")
}

func (container *recoveryPostgreSQLContainer) assertToolVersions() error {
	for _, tool := range []string{"pg_dump", "pg_restore"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		output, err := container.docker.command(ctx, "exec", container.name, tool, "--version").CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("run recovery %s version probe: %w: %s", tool, err, sanitizeToolOutput(output))
		}
		if !strings.Contains(string(output), "PostgreSQL) 18.4") {
			return fmt.Errorf("recovery %s is not PostgreSQL 18.4", tool)
		}
	}
	return nil
}

func (container *recoveryPostgreSQLContainer) remove(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := container.docker.command(ctx, "rm", "--force", container.name).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(output)), "no such container") {
		t.Errorf("remove isolated PostgreSQL recovery container: %v: %s", err, sanitizeToolOutput(output))
	}
}

func connectAndInspectRecoveryPostgreSQL(
	container *recoveryPostgreSQLContainer,
) (*pgxpool.Pool, string, error) {
	connectionURL := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(container.username, container.password),
		Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(int(container.hostPort))),
		Path:   container.databaseName,
	}
	query := connectionURL.Query()
	query.Set("sslmode", "disable")
	connectionURL.RawQuery = query.Encode()
	config, err := pgxpool.ParseConfig(connectionURL.String())
	if err != nil {
		return nil, "", errors.New("construct isolated PostgreSQL connection configuration")
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = "public"
	if config.MaxConns < 12 {
		config.MaxConns = 12
	}
	deadline := time.Now().Add(15 * time.Second)
	var pool *pgxpool.Pool
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		pool, err = pgxpool.NewWithConfig(ctx, config)
		if err == nil {
			err = pool.Ping(ctx)
		}
		cancel()
		if err == nil {
			break
		}
		if pool != nil {
			pool.Close()
			pool = nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	if pool == nil {
		return nil, "", errors.New("connect to isolated PostgreSQL container through its loopback port")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var serverVersion int
	var dataChecksums, systemIdentifier string
	err = pool.QueryRow(ctx, `
		SELECT current_setting('server_version_num')::integer,
		       current_setting('data_checksums'),
		       (SELECT system_identifier::text FROM pg_control_system())
	`).Scan(&serverVersion, &dataChecksums, &systemIdentifier)
	if err != nil {
		pool.Close()
		return nil, "", errors.New("inspect isolated PostgreSQL server controls")
	}
	if serverVersion != 180004 {
		pool.Close()
		return nil, "", fmt.Errorf("isolated recovery server version=%d, want 180004", serverVersion)
	}
	if dataChecksums != "on" {
		pool.Close()
		return nil, "", errors.New("isolated recovery server data checksums are disabled")
	}
	if systemIdentifier == "" {
		pool.Close()
		return nil, "", errors.New("isolated recovery server system_identifier is empty")
	}
	return pool, systemIdentifier, nil
}

func logicalDumpDatabase(t *testing.T, container *recoveryPostgreSQLContainer) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := container.docker.command(ctx,
		"exec", container.name,
		"pg_dump", "--format=custom", "--no-owner", "--no-acl",
		"--username", container.username, "--dbname", container.databaseName,
	)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	backup, err := command.Output()
	if err != nil {
		t.Fatalf("pg_dump recovery source database inside its container: %v: %s", err, container.sanitizeToolOutput(stderr.Bytes()))
	}
	return backup
}

func restoreLogicalDump(t *testing.T, container *recoveryPostgreSQLContainer, backup []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := container.docker.command(ctx,
		"exec", "--interactive", container.name,
		"pg_restore", "--exit-on-error", "--single-transaction", "--no-owner", "--no-acl",
		"--username", container.username, "--dbname", container.databaseName,
	)
	command.Stdin = bytes.NewReader(backup)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("pg_restore recovery target database inside its container: %v: %s", err, container.sanitizeToolOutput(stderr.Bytes()))
	}
}

func (container *recoveryPostgreSQLContainer) sanitizeToolOutput(output []byte) string {
	return strings.NewReplacer(
		container.username, "<redacted-user>",
		container.password, "<redacted-password>",
		container.databaseName, "<redacted-database>",
	).Replace(sanitizeToolOutput(output))
}

func sanitizeToolOutput(output []byte) string {
	value := strings.TrimSpace(string(output))
	if value == "" {
		return "<no diagnostic output>"
	}
	if len(value) > 1024 {
		return value[:1024] + "..."
	}
	return value
}
