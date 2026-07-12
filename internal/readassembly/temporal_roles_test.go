package readassembly

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigation/memory"
	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
	enumspb "go.temporal.io/api/enums/v1"
	namespacepb "go.temporal.io/api/namespace/v1"
	workflowservicepb "go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestSnapshotCreatesOnlyExactMTLSRuntimeV2TemporalRoles(t *testing.T) {
	endpoint, roots, certificate := startRuntimeV2TemporalMTLSServer(t)
	options := investigationworkflow.RuntimeV2ClientOptions{
		HostPort: endpoint, Namespace: "default", ServerName: "temporal.read.test",
		RootCAs: roots, Certificate: certificate,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	starterClient, err := investigationworkflow.DialRuntimeV2StarterClient(ctx, options)
	if err != nil {
		t.Fatalf("DialRuntimeV2StarterClient() error = %v", err)
	}
	t.Cleanup(func() { _ = starterClient.Close() })
	controlClient, err := investigationworkflow.DialRuntimeV2ControlClient(ctx, options)
	if err != nil {
		t.Fatalf("DialRuntimeV2ControlClient() error = %v", err)
	}
	t.Cleanup(func() { _ = controlClient.Close() })

	fixture := newSnapshotFixture(t)
	snapshot, err := LoadFiles(context.Background(), fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := memory.New(memory.Options{
		Clock:     func() time.Time { return time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC) },
		IDFactory: func() string { return "a0000000-0000-4000-8000-000000000003" },
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
	starter, controlWorker, err := snapshot.NewRuntimeV2TemporalRoles(
		starterClient, controlClient, repository, repository, recovery,
	)
	if err != nil || starter == nil || controlWorker == nil {
		t.Fatalf("NewRuntimeV2TemporalRoles() = %#v, %#v, %v", starter, controlWorker, err)
	}
	if err := controlWorker.Stop(); err != nil {
		t.Fatalf("Control Worker Stop() error = %v", err)
	}

	foreignOptions := options
	foreignOptions.Namespace = "foreign"
	foreignControlClient, err := investigationworkflow.DialRuntimeV2ControlClient(ctx, foreignOptions)
	if err != nil {
		t.Fatalf("DialRuntimeV2ControlClient(foreign namespace) error = %v", err)
	}
	defer foreignControlClient.Close()
	starter, controlWorker, err = snapshot.NewRuntimeV2TemporalRoles(
		starterClient, foreignControlClient, repository, repository, recovery,
	)
	if starter != nil || controlWorker != nil ||
		!errors.Is(err, investigationworkflow.ErrInvalidRuntimeV2Input) {
		t.Fatalf("NewRuntimeV2TemporalRoles(foreign namespace) = %#v, %#v, %v", starter, controlWorker, err)
	}
	foreignEndpoint, foreignRoots, foreignCertificate := startRuntimeV2TemporalMTLSServer(t)
	foreignEndpointControl, err := investigationworkflow.DialRuntimeV2ControlClient(
		ctx,
		investigationworkflow.RuntimeV2ClientOptions{
			HostPort: foreignEndpoint, Namespace: "default", ServerName: "temporal.read.test",
			RootCAs: foreignRoots, Certificate: foreignCertificate,
		},
	)
	if err != nil {
		t.Fatalf("DialRuntimeV2ControlClient(foreign endpoint) error = %v", err)
	}
	defer foreignEndpointControl.Close()
	starter, controlWorker, err = snapshot.NewRuntimeV2TemporalRoles(
		starterClient, foreignEndpointControl, repository, repository, recovery,
	)
	if starter != nil || controlWorker != nil ||
		!errors.Is(err, investigationworkflow.ErrInvalidRuntimeV2Input) {
		t.Fatalf("NewRuntimeV2TemporalRoles(foreign endpoint) = %#v, %#v, %v", starter, controlWorker, err)
	}

	starterCopy := *starterClient
	starter, controlWorker, err = snapshot.NewRuntimeV2TemporalRoles(
		&starterCopy, controlClient, repository, repository, recovery,
	)
	if starter != nil || controlWorker != nil ||
		!errors.Is(err, investigationworkflow.ErrInvalidRuntimeV2Input) {
		t.Fatalf("NewRuntimeV2TemporalRoles(copied client) = %#v, %#v, %v", starter, controlWorker, err)
	}
	starter, controlWorker, err = snapshot.NewRuntimeV2TemporalRoles(
		starterClient, controlClient, nil, repository, recovery,
	)
	if starter != nil || controlWorker != nil ||
		!errors.Is(err, investigationworkflow.ErrInvalidRuntimeV2Input) {
		t.Fatalf("NewRuntimeV2TemporalRoles(nil reader) = %#v, %#v, %v", starter, controlWorker, err)
	}

	var _ investigation.SignalRegistrationReader = repository
}

type runtimeV2TemporalHealthServer struct {
	workflowservicepb.UnimplementedWorkflowServiceServer
}

func (*runtimeV2TemporalHealthServer) GetSystemInfo(
	context.Context,
	*workflowservicepb.GetSystemInfoRequest,
) (*workflowservicepb.GetSystemInfoResponse, error) {
	return &workflowservicepb.GetSystemInfoResponse{
		Capabilities: &workflowservicepb.GetSystemInfoResponse_Capabilities{},
	}, nil
}

func (*runtimeV2TemporalHealthServer) GetClusterInfo(
	context.Context,
	*workflowservicepb.GetClusterInfoRequest,
) (*workflowservicepb.GetClusterInfoResponse, error) {
	return &workflowservicepb.GetClusterInfoResponse{
		ClusterId: "00000000-0000-4000-8000-000000000101", ClusterName: "runtime-v2-assembly-test",
	}, nil
}

func (*runtimeV2TemporalHealthServer) DescribeNamespace(
	_ context.Context,
	request *workflowservicepb.DescribeNamespaceRequest,
) (*workflowservicepb.DescribeNamespaceResponse, error) {
	namespaceID := "00000000-0000-4000-8000-000000000110"
	if request.GetNamespace() != "default" {
		namespaceID = "00000000-0000-4000-8000-000000000111"
	}
	return &workflowservicepb.DescribeNamespaceResponse{NamespaceInfo: &namespacepb.NamespaceInfo{
		Name: request.GetNamespace(), Id: namespaceID, State: enumspb.NAMESPACE_STATE_REGISTERED,
	}}, nil
}

func startRuntimeV2TemporalMTLSServer(t *testing.T) (string, *x509.CertPool, tls.Certificate) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := testpki.NewAuthority("temporal-read-test-root", now)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, err := authority.IssueServer("temporal.read.test", now)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := authority.IssueClient(testpki.ClientOptions{}, now)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate.TLS},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    authority.CertPool(),
		NextProtos:   []string{"h2"},
	})))
	workflowservicepb.RegisterWorkflowServiceServer(server, &runtimeV2TemporalHealthServer{})
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		select {
		case serveErr := <-serveErrors:
			if serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
				t.Errorf("mTLS Temporal test server error = %v", serveErr)
			}
		case <-time.After(time.Second):
			t.Error("mTLS Temporal test server did not stop")
		}
	})
	return listener.Addr().String(), authority.CertPool(), clientCertificate.TLS
}
