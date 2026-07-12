package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"

	"github.com/seaworld008/aiops-system/internal/config"
	"github.com/seaworld008/aiops-system/internal/credential"
	credentialpostgres "github.com/seaworld008/aiops-system/internal/credential/postgres"
	executionpostgres "github.com/seaworld008/aiops-system/internal/execution/postgres"
	"github.com/seaworld008/aiops-system/internal/ids"
	"github.com/seaworld008/aiops-system/internal/readgateway"
	"github.com/seaworld008/aiops-system/internal/readtask"
	readtaskpostgres "github.com/seaworld008/aiops-system/internal/readtask/postgres"
	"github.com/seaworld008/aiops-system/internal/runnergateway"
	runnergatewaypostgres "github.com/seaworld008/aiops-system/internal/runnergateway/postgres"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
	runneridentitypostgres "github.com/seaworld008/aiops-system/internal/runneridentity/postgres"
)

type runnerGatewayDatabase interface {
	credentialpostgres.DB
}

// runnerGatewayRuntime owns the process-local credential protection keys and
// the TLS-only listener boundary. Destroy must run after the listener drains.
type runnerGatewayRuntime struct {
	server    *runnergateway.GatewayServer
	protector *credential.AESGCMProtector
}

func newRunnerGatewayRuntime(
	configuration *config.RunnerGatewayConfig,
	mode config.WriteExecutionMode,
	database runnerGatewayDatabase,
) (*runnerGatewayRuntime, error) {
	if configuration == nil {
		return nil, nil
	}
	if database == nil {
		return nil, fmt.Errorf("Runner Gateway requires PostgreSQL")
	}

	verifier, tlsConfiguration, err := runneridentity.LoadFiles(runneridentity.FileOptions{
		ServerCertFile: configuration.ServerCertFile, ServerKeyFile: configuration.ServerKeyFile,
		ReadClientCAFile: configuration.ReadClientCAFile, WriteClientCAFile: configuration.WriteClientCAFile,
		TrustDomain: configuration.TrustDomain,
	})
	if err != nil {
		return nil, fmt.Errorf("load Runner Gateway identity files: %w", err)
	}
	protector, err := credential.LoadAESGCMProtectorFile(configuration.CredentialKeyringFile)
	if err != nil {
		return nil, fmt.Errorf("load Runner Gateway credential protection keyring: %w", err)
	}
	fail := func(operation string, cause error) (*runnerGatewayRuntime, error) {
		protector.Destroy()
		return nil, fmt.Errorf("%s: %w", operation, cause)
	}

	identities, err := runneridentitypostgres.New(database)
	if err != nil {
		return fail("configure Runner identity repository", err)
	}
	executions, err := executionpostgres.New(database, executionpostgres.Options{})
	if err != nil {
		return fail("configure Runner execution repository", err)
	}
	credentials, err := credentialpostgres.New(database, protector, credentialpostgres.Options{})
	if err != nil {
		return fail("configure Runner credential repository", err)
	}
	backend, err := runnergatewaypostgres.New(runnergatewaypostgres.Dependencies{
		Database: database, Identities: identities, Executions: executions, Credentials: credentials,
		WriteExecutionMode: mode,
		// WRITE deliberately has no final policy/target authorizer. New job
		// claims remain fail-closed until M6 supplies fixed non-production
		// adapters; no production-write mode exists.
		StartAuthorizer: nil,
	})
	if err != nil {
		return fail("configure Runner Gateway PostgreSQL backend", err)
	}
	readTasks, err := readtaskpostgres.New(database, readtaskpostgres.Options{
		TokenSource: readTaskLeaseEntropy,
		IDSource:    ids.NewUUID,
	})
	if err != nil {
		return fail("configure READ task repository", err)
	}
	readBackend, err := readgateway.New(readgateway.Dependencies{
		Database: database, Identities: identities, Tasks: readTasks,
		// The protocol remains closed as one indivisible admission state. A
		// later runtime bundle may replace these placeholder authorizers, but
		// assembly alone must not let a new or pre-existing lease progress.
		Admission:            readgateway.NewClosedAdmission(),
		StartAuthorizer:      disabledReadTaskStart,
		CompletionAuthorizer: disabledReadTaskCompletion,
	})
	if err != nil {
		return fail("configure READ Task Gateway backend", err)
	}
	handler, err := runnergateway.NewRouterWithReadTasks(verifier, backend, readBackend)
	if err != nil {
		return fail("configure Runner Gateway protocol", err)
	}
	server, err := runnergateway.NewGatewayServer(configuration.Addr, handler, tlsConfiguration)
	if err != nil {
		return fail("configure Runner Gateway TLS server", err)
	}
	return &runnerGatewayRuntime{server: server, protector: protector}, nil
}

func readTaskLeaseEntropy() ([]byte, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		clear(value)
		return nil, fmt.Errorf("generate READ task lease entropy: %w", err)
	}
	return value, nil
}

func disabledReadTaskStart(context.Context, readtask.Descriptor) error {
	return readtask.ErrClaimsDisabled
}

func disabledReadTaskCompletion(context.Context, readtask.Descriptor, readtask.EvidenceCompletion) error {
	return readtask.ErrClaimsDisabled
}

func (runtime *runnerGatewayRuntime) Serve(listener net.Listener) error {
	if runtime == nil || runtime.server == nil {
		return fmt.Errorf("Runner Gateway runtime is unavailable")
	}
	return runtime.server.Serve(listener)
}

func (runtime *runnerGatewayRuntime) Shutdown(ctx context.Context) error {
	if runtime == nil || runtime.server == nil {
		return nil
	}
	return runtime.server.Shutdown(ctx)
}

func (runtime *runnerGatewayRuntime) Destroy() {
	if runtime == nil || runtime.protector == nil {
		return
	}
	runtime.protector.Destroy()
	runtime.protector = nil
}
