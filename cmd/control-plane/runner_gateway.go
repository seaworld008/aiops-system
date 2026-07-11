package main

import (
	"context"
	"fmt"
	"net"

	"github.com/seaworld008/aiops-system/internal/config"
	"github.com/seaworld008/aiops-system/internal/credential"
	credentialpostgres "github.com/seaworld008/aiops-system/internal/credential/postgres"
	executionpostgres "github.com/seaworld008/aiops-system/internal/execution/postgres"
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
		// M3 deliberately has no final policy/target authorizer. New job claims
		// remain fail-closed until M4 supplies the isolated execution path.
		StartAuthorizer: nil,
	})
	if err != nil {
		return fail("configure Runner Gateway PostgreSQL backend", err)
	}
	handler, err := runnergateway.NewRouter(verifier, backend)
	if err != nil {
		return fail("configure Runner Gateway protocol", err)
	}
	server, err := runnergateway.NewGatewayServer(configuration.Addr, handler, tlsConfiguration)
	if err != nil {
		return fail("configure Runner Gateway TLS server", err)
	}
	return &runnerGatewayRuntime{server: server, protector: protector}, nil
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
