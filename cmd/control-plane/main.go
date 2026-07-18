package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/authz"
	"github.com/seaworld008/aiops-system/internal/buildinfo"
	"github.com/seaworld008/aiops-system/internal/config"
	credentialpostgres "github.com/seaworld008/aiops-system/internal/credential/postgres"
	"github.com/seaworld008/aiops-system/internal/credentialadmin"
	"github.com/seaworld008/aiops-system/internal/httpapi"
	"github.com/seaworld008/aiops-system/internal/ids"
	signalservice "github.com/seaworld008/aiops-system/internal/signal"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
	postgresstore "github.com/seaworld008/aiops-system/internal/store/postgres"
	"github.com/seaworld008/aiops-system/internal/webhook"
)

func main() {
	if err := run(); err != nil {
		slog.Error("control plane stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	var databasePool *pgxpool.Pool
	var dependencyFailure error
	if cfg.DatabaseURL == "" {
		dependencyFailure = errors.Join(dependencyFailure, errors.New("PostgreSQL is unavailable"))
	} else {
		connectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		databasePool, err = pgxpool.New(connectCtx, cfg.DatabaseURL)
		if err == nil {
			err = databasePool.Ping(connectCtx)
		}
		cancel()
		if err != nil {
			if databasePool != nil {
				databasePool.Close()
				databasePool = nil
			}
			dependencyFailure = errors.Join(dependencyFailure, errors.New("PostgreSQL is unavailable"))
		} else {
			defer databasePool.Close()
		}
	}

	var signalIngestor httpapi.SignalIngestor
	if databasePool != nil {
		var repository signalservice.Repository = postgresstore.New(databasePool)
		signalIngestor = signalservice.NewService(repository, time.Now)
	}
	webhookVerifier := webhook.NewHMACVerifier(func(integrationID, provider string) ([]byte, error) {
		if secret := cfg.WebhookHMACSecrets[integrationID+"/"+provider]; secret != "" {
			return []byte(secret), nil
		}
		if cfg.Environment != "production" && cfg.WebhookHMACSecret != "" {
			return []byte(cfg.WebhookHMACSecret), nil
		}
		return nil, webhook.ErrSecretUnavailable
	})

	var authenticator *authn.Authenticator
	if cfg.OIDCIssuer != "" {
		discoveryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		keycloakVerifier, verifierErr := authn.NewKeycloakVerifier(
			discoveryCtx, cfg.OIDCIssuer, cfg.OIDCAPIAudience, cfg.OIDCAuthorizedParty,
		)
		cancel()
		if verifierErr != nil {
			dependencyFailure = errors.Join(dependencyFailure, errors.New("OIDC verification is unavailable"))
		} else {
			authenticator, err = authn.NewAuthenticator(
				keycloakVerifier, authn.Options{MaxSessionAge: cfg.OIDCMaxSessionAge}, time.Now,
			)
			if err != nil {
				dependencyFailure = errors.Join(dependencyFailure, errors.New("OIDC authentication is unavailable"))
				authenticator = nil
			}
		}
	} else {
		dependencyFailure = errors.Join(dependencyFailure, errors.New("OIDC authentication is unavailable"))
	}

	var browserConfig *httpapi.BrowserConfig
	if cfg.WebOIDCURL != "" {
		browserConfig, err = httpapi.NewBrowserConfig(httpapi.BrowserConfigInput{
			OIDCURL: cfg.WebOIDCURL, OIDCRealm: cfg.WebOIDCRealm, OIDCClientID: cfg.WebOIDCClientID,
			Version: buildinfo.Version, Commit: buildinfo.Commit,
			ContractDigest: httpapi.ControlPlaneContractDigest(),
		})
		if err != nil {
			dependencyFailure = errors.Join(dependencyFailure, errors.New("browser configuration is unavailable"))
			browserConfig = nil
		}
	} else {
		dependencyFailure = errors.Join(dependencyFailure, errors.New("browser configuration is unavailable"))
	}

	webUI, err := newOptionalWebUI(cfg.WebRoot, cfg.WebOIDCURL)
	if err != nil {
		return fmt.Errorf("initialize Web UI: %w", err)
	}
	if webUI != nil {
		defer webUI.Close()
	}

	var cursorCodec *httpapi.ControlPlaneCursorCodec
	cursorCodec, err = httpapi.NewControlPlaneCursorCodec(cfg.ControlPlaneCursorHMACSecret)
	if err != nil {
		dependencyFailure = errors.Join(dependencyFailure, errors.New("Control Plane cursor signing is unavailable"))
		cursorCodec = nil
	}

	authorizer, authorizerErr := authz.NewAuthorizer(cfg.OIDCRecentAuthWindow, time.Now)
	if authorizerErr != nil {
		dependencyFailure = errors.Join(dependencyFailure, errors.New("authorization is unavailable"))
		authorizer = nil
	}

	var credentialRevocations httpapi.CredentialRevocationManager
	if databasePool != nil && authorizer != nil {
		managementStore, managementErr := credentialpostgres.NewManagement(databasePool)
		if managementErr != nil {
			dependencyFailure = errors.Join(dependencyFailure, errors.New("credential revocation management is unavailable"))
		} else {
			credentialRevocations, err = credentialadmin.New(managementStore, authorizer)
			if err != nil {
				dependencyFailure = errors.Join(dependencyFailure, errors.New("credential revocation management is unavailable"))
				credentialRevocations = nil
			}
		}
	}

	var assetCatalogAdmission *assetpostgres.SchemaAdmission
	if databasePool != nil {
		assetCatalogAdmission = assetpostgres.NewSchemaAdmission(databasePool, "public")
	}
	assemblyCtx, assemblyCancel := context.WithTimeout(context.Background(), 10*time.Second)
	assetAssembly, assemblyErr := newAssetCatalogAssembly(
		assemblyCtx, databasePool, authorizer, cursorCodec, assetCatalogAdmission,
		cfg.ExternalCMDBProfile,
	)
	assemblyCancel()
	if assemblyErr != nil {
		dependencyFailure = errors.Join(dependencyFailure, errors.New("asset catalog is unavailable"))
	}

	dependencyReady := func() error {
		if dependencyFailure != nil || databasePool == nil || assetAssembly.Admission == nil {
			return errors.New("control plane dependencies are unavailable")
		}
		pingCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := databasePool.Ping(pingCtx); err != nil {
			return errors.New("control plane dependencies are unavailable")
		}
		if err := assetAssembly.Admission.Check(pingCtx); err != nil {
			return errors.New("control plane dependencies are unavailable")
		}
		return nil
	}
	readinessChecks := []func() error{dependencyReady}
	if webUI != nil {
		readinessChecks = append(readinessChecks, webUI.Ready)
	}
	ready := combineReadiness(readinessChecks...)

	publicServer := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpapi.NewRouter(httpapi.Dependencies{
			Version:               buildinfo.Version,
			Ready:                 ready,
			SignalIngestor:        signalIngestor,
			WebhookVerifier:       webhookVerifier,
			Authenticator:         authenticator,
			CredentialRevocations: credentialRevocations,
			BrowserConfig:         browserConfig,
			ControlPlaneCursor:    cursorCodec,
			Assets:                assetAssembly.Assets,
			AssetRelations:        assetAssembly.AssetRelations,
			AssetSources:          assetAssembly.AssetSources,
			AssetConflicts:        assetAssembly.AssetConflicts,
			ServiceAssetBindings:  assetAssembly.ServiceAssetBindings,
			WebUI:                 webUI,
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	var gatewayRuntime *runnerGatewayRuntime
	if databasePool != nil {
		gatewayRuntime, err = newRunnerGatewayRuntime(cfg.RunnerGateway, cfg.WriteExecutionMode, databasePool)
		if err != nil {
			return err
		}
	} else if cfg.RunnerGateway != nil {
		dependencyFailure = errors.Join(dependencyFailure, errors.New("Runner Gateway is unavailable"))
	}
	if gatewayRuntime != nil {
		defer gatewayRuntime.Destroy()
	}

	publicListener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen on public API address: %w", err)
	}
	defer publicListener.Close()
	var gatewayListener net.Listener
	if gatewayRuntime != nil {
		gatewayListener, err = net.Listen("tcp", cfg.RunnerGateway.Addr)
		if err != nil {
			return fmt.Errorf("listen on Runner Gateway address: %w", err)
		}
		defer gatewayListener.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	serveErrors := make(chan error, 2)
	serve := func(component string, function func() error) {
		if serveErr := function(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) &&
			!errors.Is(serveErr, net.ErrClosed) {
			serveErrors <- fmt.Errorf("serve %s: %w", component, serveErr)
		}
	}

	slog.Info("control plane listening", "addr", cfg.HTTPAddr, "environment", cfg.Environment)
	go serve("public API", func() error { return publicServer.Serve(publicListener) })
	if gatewayRuntime != nil {
		slog.Info("Runner Gateway listening", "addr", cfg.RunnerGateway.Addr, "write_execution_mode", cfg.WriteExecutionMode)
		go serve("Runner Gateway", func() error { return gatewayRuntime.Serve(gatewayListener) })
	}

	var serveFailure error
	select {
	case <-ctx.Done():
	case serveFailure = <-serveErrors:
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	shutdownCount := 1
	if gatewayRuntime != nil {
		shutdownCount++
	}
	shutdownErrors := make(chan error, shutdownCount)
	go func() { shutdownErrors <- publicServer.Shutdown(shutdownCtx) }()
	if gatewayRuntime != nil {
		go func() { shutdownErrors <- gatewayRuntime.Shutdown(shutdownCtx) }()
	}
	var shutdownFailure error
	for range shutdownCount {
		shutdownFailure = errors.Join(shutdownFailure, <-shutdownErrors)
	}
	return errors.Join(serveFailure, shutdownFailure)
}

func combineReadiness(checks ...func() error) func() error {
	return func() error {
		for _, check := range checks {
			if check == nil {
				return errors.New("readiness dependency is unavailable")
			}
			if err := check(); err != nil {
				return err
			}
		}
		return nil
	}
}

func newOptionalWebUI(root, oidcURL string) (*httpapi.WebUI, error) {
	if root == "" {
		return nil, nil
	}
	return httpapi.NewWebUI(root, oidcURL)
}

type assetCatalogAssembly struct {
	Assets               assetcatalog.AssetManager
	AssetRelations       assetcatalog.RelationshipManager
	AssetSources         assetcatalog.SourceManager
	AssetConflicts       assetcatalog.ConflictManager
	ServiceAssetBindings assetcatalog.BindingManager
	Admission            *assetpostgres.SchemaAdmission
}

type sourceProfileAssembly struct {
	registry            assetcatalog.SourceProfileRegistry
	validationAdmission sourceprofile.SourceValidationRuntimeAdmission
}

func newSourceProfileAssembly(
	externalCMDB *config.ExternalCMDBProfileConfig,
) (sourceProfileAssembly, error) {
	if externalCMDB == nil {
		return sourceProfileAssembly{
			registry: assetcatalog.NewBuiltinSourceProfileRegistry(),
		}, nil
	}
	descriptor := sourceprofile.ExternalCMDBV1()
	registration, err := descriptor.Registration(sourceprofile.ExternalCMDBProfileReferences{
		IntegrationID: externalCMDB.IntegrationID,
		CredentialReferenceID: assetcatalog.CredentialReferenceID(
			externalCMDB.CredentialReferenceID,
		),
		TrustReferenceID: assetcatalog.TrustReferenceID(
			externalCMDB.TrustReferenceID,
		),
		NetworkPolicyReferenceID: assetcatalog.NetworkPolicyReferenceID(
			externalCMDB.NetworkPolicyReferenceID,
		),
	})
	if err != nil {
		return sourceProfileAssembly{}, errors.New("external CMDB profile registration is unavailable")
	}
	registry, err := assetcatalog.NewSourceProfileRegistry(registration)
	if err != nil {
		return sourceProfileAssembly{}, errors.New("external CMDB profile registry is unavailable")
	}
	validationAdmission, err := sourceprofile.NewSourceValidationRuntimeAdmission(
		descriptor,
		sourceprofile.SourceValidationRuntimeManifest{
			CanonicalJSON: externalCMDB.RuntimeAdmissionManifestJSON,
			DigestSHA256:  externalCMDB.RuntimeAdmissionManifestSHA256,
		},
	)
	if err != nil {
		return sourceProfileAssembly{}, errors.New("external CMDB validation admission is unavailable")
	}
	return sourceProfileAssembly{
		registry: registry, validationAdmission: validationAdmission,
	}, nil
}

func newAssetCatalogAssembly(
	ctx context.Context,
	databasePool *pgxpool.Pool,
	authorizer *authz.Authorizer,
	cursorCodec *httpapi.ControlPlaneCursorCodec,
	admission *assetpostgres.SchemaAdmission,
	externalCMDBProfiles ...*config.ExternalCMDBProfileConfig,
) (assetCatalogAssembly, error) {
	if ctx == nil || databasePool == nil || authorizer == nil || cursorCodec == nil ||
		admission == nil || len(externalCMDBProfiles) > 1 {
		return assetCatalogAssembly{}, errors.New("asset catalog dependencies are unavailable")
	}
	if err := admission.Check(ctx); err != nil {
		return assetCatalogAssembly{}, errors.New("asset catalog schema is unavailable")
	}
	var externalCMDBProfile *config.ExternalCMDBProfileConfig
	if len(externalCMDBProfiles) == 1 {
		externalCMDBProfile = externalCMDBProfiles[0]
	}
	profiles, err := newSourceProfileAssembly(externalCMDBProfile)
	if err != nil {
		return assetCatalogAssembly{}, errors.New("asset catalog source profiles are unavailable")
	}
	var repository *assetpostgres.Repository
	if profiles.validationAdmission.Valid() {
		repository, err = assetpostgres.NewWithSourceProfileRegistry(
			databasePool,
			time.Now,
			ids.NewUUID,
			profiles.registry,
			profiles.validationAdmission,
		)
	} else {
		repository, err = assetpostgres.NewWithSourceProfileRegistry(
			databasePool,
			time.Now,
			ids.NewUUID,
			profiles.registry,
		)
	}
	if err != nil {
		return assetCatalogAssembly{}, errors.New("asset catalog repository is unavailable")
	}
	management, err := assetcatalog.NewManagement(repository, repository, repository, authorizer)
	if err != nil {
		return assetCatalogAssembly{}, errors.New("asset catalog management is unavailable")
	}
	return assetCatalogAssembly{
		Assets: management, AssetRelations: management, AssetSources: management,
		AssetConflicts: management, ServiceAssetBindings: management,
		Admission: admission,
	}, nil
}
