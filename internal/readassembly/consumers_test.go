package readassembly

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigation/memory"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readgateway"
	"github.com/seaworld008/aiops-system/internal/readrunneractivity"
	"github.com/seaworld008/aiops-system/internal/readrunnerclient"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"github.com/seaworld008/aiops-system/internal/runneridentity"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

func TestSnapshotCreatesRuntimeV2ActivitiesWithoutExportingRawPlanningComponents(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadFiles(context.Background(), fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := memory.New(memory.Options{
		Clock:     func() time.Time { return time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC) },
		IDFactory: func() string { return "a0000000-0000-4000-8000-000000000001" },
		TenantResolver: func(string) (string, error) {
			return snapshotTenantID, nil
		},
		TaskSpecAuthorizer: snapshot.AuthorizeTaskSpec,
		TaskRuntimeBinder:  snapshot.Bind,
	})
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := investigationworkflow.NewRecoveryActivities(snapshotRecoveryReader{})
	if err != nil {
		t.Fatal(err)
	}
	activities, err := snapshot.NewRuntimeV2Activities(repository, repository, recovery, "default")
	if err != nil || activities == nil {
		t.Fatalf("NewRuntimeV2Activities() = %#v, %v", activities, err)
	}
	summary := snapshot.Summary()
	queue, err := investigationworkflow.ControlTaskQueue(
		summary.PlanManifestDigest, summary.ConnectorRegistryDigest, summary.BundleDigest,
	)
	if err != nil || queue == "" {
		t.Fatalf("ControlTaskQueue(Snapshot Summary) = %q, %v", queue, err)
	}
	runnerQueue, err := investigationworkflow.RunnerTaskQueue(
		snapshotEnvironmentID,
		summary.PlanManifestDigest,
		summary.ConnectorRegistryDigest,
		summary.BundleDigest,
	)
	if err != nil || runnerQueue == "" || runnerQueue == queue {
		t.Fatalf("RunnerTaskQueue(Snapshot Summary) = %q, %v", runnerQueue, err)
	}

	copy := *snapshot
	if activities, err := copy.NewRuntimeV2Activities(repository, repository, recovery, "default"); activities != nil || !errors.Is(err, investigationworkflow.ErrInvalidRuntimeV2Input) {
		t.Fatalf("copied Snapshot NewRuntimeV2Activities() = %#v, %v", activities, err)
	}
	if activities, err := snapshot.NewRuntimeV2Activities(nil, repository, recovery, "default"); activities != nil || !errors.Is(err, investigationworkflow.ErrInvalidRuntimeV2Input) {
		t.Fatalf("NewRuntimeV2Activities(nil reader) = %#v, %v", activities, err)
	}
}

func TestSnapshotCreatesReadRunnerActivitiesWithoutExportingRawBundle(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadFiles(context.Background(), fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	client := newSnapshotReadRunnerClient(t)
	defer client.CloseIdleConnections()
	credentials := readexecutor.BearerSource(func(_ context.Context, _ string, use func([]byte)) readtask.FailureCode {
		if use == nil {
			return readtask.FailureUnknown
		}
		token := []byte("snapshot-test-bearer-1234567890")
		defer clear(token)
		use(token)
		return ""
	})
	activities, err := snapshot.NewReadRunnerActivities(client, credentials, "default")
	if err != nil || activities == nil {
		t.Fatalf("NewReadRunnerActivities() = %#v, %v", activities, err)
	}
	summary := snapshot.Summary()
	if !activities.AcceptsPlanningIdentity(
		summary.PlanManifestDigest, summary.ConnectorRegistryDigest, summary.BundleDigest,
	) {
		t.Fatal("READ Runner Activities are not bound to the Snapshot planning identity")
	}
	for name, mutate := range map[string]func(*Summary){
		"foreign Plan": func(value *Summary) {
			value.PlanManifestDigest = foreignSnapshotDigest(value.PlanManifestDigest)
		},
		"foreign Registry": func(value *Summary) {
			value.ConnectorRegistryDigest = foreignSnapshotDigest(value.ConnectorRegistryDigest)
		},
		"foreign Bundle": func(value *Summary) {
			value.BundleDigest = foreignSnapshotDigest(value.BundleDigest)
		},
	} {
		t.Run(name, func(t *testing.T) {
			foreign := summary
			mutate(&foreign)
			if activities.AcceptsPlanningIdentity(
				foreign.PlanManifestDigest, foreign.ConnectorRegistryDigest, foreign.BundleDigest,
			) {
				t.Fatal("READ Runner Activities accepted a foreign planning identity")
			}
		})
	}

	copy := *snapshot
	if activities, err := copy.NewReadRunnerActivities(client, credentials, "default"); activities != nil || !errors.Is(err, readrunneractivity.ErrActivityRejected) {
		t.Fatalf("copied Snapshot NewReadRunnerActivities() = %#v, %v", activities, err)
	}
	if activities, err := snapshot.NewReadRunnerActivities(client, nil, "default"); activities != nil || !errors.Is(err, readrunneractivity.ErrActivityRejected) {
		t.Fatalf("NewReadRunnerActivities(nil credentials) = %#v, %v", activities, err)
	}
}

func TestSnapshotFacadeMethodValuesMatchPersistenceAndGatewayContracts(t *testing.T) {
	fixture := newSnapshotFixture(t)
	snapshot, err := LoadFiles(context.Background(), fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	var taskAuthorizer investigation.TaskSpecAuthorizer = snapshot.AuthorizeTaskSpec
	var taskBinder investigation.TaskRuntimeBinder = snapshot.Bind
	var startAuthorizer readgateway.StartAuthorizer = snapshot.AuthorizeStart
	var heartbeatAuthorizer readgateway.HeartbeatAuthorizer = snapshot.AuthorizeHeartbeat
	var completionAuthorizer readgateway.CompletionAuthorizer = snapshot.AuthorizeCompletion
	if taskAuthorizer == nil || taskBinder == nil || startAuthorizer == nil ||
		heartbeatAuthorizer == nil || completionAuthorizer == nil {
		t.Fatal("Snapshot facade method value is nil")
	}
}

func stringOfDigest(value byte) string {
	result := make([]byte, 64)
	for index := range result {
		result[index] = value
	}
	return string(result)
}

func foreignSnapshotDigest(current string) string {
	candidate := stringOfDigest('a')
	if candidate == current {
		return stringOfDigest('b')
	}
	return candidate
}

type snapshotRecoveryReader struct{}

func (snapshotRecoveryReader) Recover(context.Context, readtask.RecoveryRequest) (readtask.RecoveryResult, error) {
	return readtask.RecoveryResult{}, errors.New("unused snapshot recovery reader")
}

func newSnapshotReadRunnerClient(t *testing.T) *readrunnerclient.Client {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := testpki.NewAuthority("read-snapshot-client-root", now)
	if err != nil {
		t.Fatal(err)
	}
	spiffe, err := url.Parse("spiffe://aiops.test/runner/read/snapshot-runner-1")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := authority.IssueClient(testpki.ClientOptions{URIs: []*url.URL{spiffe}}, now)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	rootFile := filepath.Join(directory, "server-root.pem")
	certificateFile := filepath.Join(directory, "client-chain.pem")
	keyFile := filepath.Join(directory, "client-key.pem")
	writeSnapshotBytes(t, rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.Certificate.Raw}))
	var chain []byte
	for _, raw := range certificate.TLS.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})...)
	}
	writeSnapshotBytes(t, certificateFile, chain)
	privateKey, ok := certificate.TLS.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T", certificate.TLS.PrivateKey)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	writeSnapshotBytes(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}))
	client, err := readrunnerclient.New(readrunnerclient.Options{
		BaseURL: "https://read-runner-gateway.test:8443", ServerName: "read-runner-gateway.test",
		TrustDomain: "aiops.test", ExpectedPool: runneridentity.PoolRead,
		RootCAFile: rootFile, ClientCertificateFile: certificateFile, ClientPrivateKeyFile: keyFile,
	})
	if err != nil {
		t.Fatalf("readrunnerclient.New() error = %v", err)
	}
	return client
}
