package investigationworkflow

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	namespacepb "go.temporal.io/api/namespace/v1"
	workflowservicepb "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestRuntimeV2ClientOptionsBuildExactTLS13MTLSRoleProfiles(t *testing.T) {
	roots, certificate := newRuntimeV2ClientPKI(
		t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	options := RuntimeV2ClientOptions{
		HostPort: "temporal.internal:7233", Namespace: "runtime-v2", ServerName: "temporal.internal",
		RootCAs: roots, Certificate: certificate,
	}
	starterOptions, err := runtimeV2SDKOptions(options, runtimeV2StarterIdentity)
	if err != nil {
		t.Fatalf("runtimeV2SDKOptions(starter) error = %v", err)
	}
	controlOptions, err := runtimeV2SDKOptions(options, runtimeV2ControlIdentity)
	if err != nil {
		t.Fatalf("runtimeV2SDKOptions(control) error = %v", err)
	}
	if starterOptions.Identity == controlOptions.Identity || starterOptions.Identity != runtimeV2StarterIdentity ||
		controlOptions.Identity != runtimeV2ControlIdentity {
		t.Fatalf("role identities = %q / %q", starterOptions.Identity, controlOptions.Identity)
	}
	for _, built := range []client.Options{starterOptions, controlOptions} {
		tlsConfiguration := built.ConnectionOptions.TLS
		if built.HostPort != options.HostPort || built.Namespace != options.Namespace || built.Credentials != nil ||
			built.HeadersProvider != nil || built.DataConverter == nil || built.FailureConverter == nil ||
			len(built.Interceptors) != 0 ||
			len(built.ConnectionOptions.DialOptions) != 1 || tlsConfiguration == nil ||
			tlsConfiguration.MinVersion != tls.VersionTLS13 || tlsConfiguration.MaxVersion != tls.VersionTLS13 ||
			tlsConfiguration.ServerName != options.ServerName || tlsConfiguration.InsecureSkipVerify ||
			tlsConfiguration.RootCAs == nil || tlsConfiguration.RootCAs == roots ||
			len(tlsConfiguration.Certificates) != 1 || len(tlsConfiguration.NextProtos) != 1 ||
			tlsConfiguration.NextProtos[0] != "h2" {
			t.Fatalf("unsafe SDK options = %#v / TLS %#v", built, tlsConfiguration)
		}
		dataConverter, ok := built.DataConverter.(*runtimeV2DataConverter)
		if !ok || !dataConverter.valid() {
			t.Fatalf("SDK converter = %T", built.DataConverter)
		}
		failureConverter, ok := built.FailureConverter.(*runtimeV2FailureConverter)
		if !ok || !failureConverter.valid() {
			t.Fatalf("SDK FailureConverter = %T", built.FailureConverter)
		}
		assertRejectedRuntimeV2Failure(t, built.FailureConverter.ErrorToFailure(
			temporal.NewApplicationError("secret-message", "PREPARE_FACT_CONFLICT", "secret-detail"),
		))
	}

	original := starterOptions.ConnectionOptions.TLS.Certificates[0].Certificate[0][0]
	originalLeafRaw := starterOptions.ConnectionOptions.TLS.Certificates[0].Leaf.Raw[0]
	certificate.Certificate[0][0] ^= 0xff
	if starterOptions.ConnectionOptions.TLS.Certificates[0].Certificate[0][0] != original ||
		starterOptions.ConnectionOptions.TLS.Certificates[0].Leaf.Raw[0] != originalLeafRaw {
		t.Fatal("SDK TLS client certificate aliases caller-owned storage")
	}
	builtPrivate, ok := starterOptions.ConnectionOptions.TLS.Certificates[0].PrivateKey.(*ecdsa.PrivateKey)
	callerPrivate, callerOK := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || !callerOK || builtPrivate == callerPrivate {
		t.Fatal("SDK TLS private key was not detached from caller-owned storage")
	}
	builtD := new(big.Int).Set(builtPrivate.D)
	builtX := new(big.Int).Set(builtPrivate.PublicKey.X)
	callerPrivate.D.SetInt64(1)
	callerPrivate.PublicKey.X.SetInt64(1)
	if builtPrivate.D.Cmp(builtD) != 0 || builtPrivate.PublicKey.X.Cmp(builtX) != 0 {
		t.Fatal("SDK TLS private key changed after caller mutation")
	}
	if fields := reflect.VisibleFields(reflect.TypeOf(RuntimeV2ClientOptions{})); len(fields) != 5 {
		t.Fatalf("RuntimeV2ClientOptions exposes %d fields, want exactly 5", len(fields))
	}
}

func TestRuntimeV2ClientDetachesCallerBackedStrings(t *testing.T) {
	hostBytes := []byte("temporal.internal:7233")
	namespaceBytes := []byte("runtime-v2")
	serverNameBytes := []byte("temporal.internal")
	host := unsafe.String(unsafe.SliceData(hostBytes), len(hostBytes))
	namespace := unsafe.String(unsafe.SliceData(namespaceBytes), len(namespaceBytes))
	serverName := unsafe.String(unsafe.SliceData(serverNameBytes), len(serverNameBytes))
	roots, certificate := newRuntimeV2ClientPKI(
		t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	built, err := runtimeV2SDKOptions(RuntimeV2ClientOptions{
		HostPort: host, Namespace: namespace, ServerName: serverName, RootCAs: roots, Certificate: certificate,
	}, runtimeV2StarterIdentity)
	if err != nil {
		t.Fatal(err)
	}
	starter, err := newRuntimeV2StarterClient(&recordingRuntimeV2StarterTransport{}, namespace)
	if err != nil {
		t.Fatal(err)
	}
	hostBytes[0], namespaceBytes[0], serverNameBytes[0] = 'X', 'X', 'X'
	if built.HostPort != "temporal.internal:7233" || built.Namespace != "runtime-v2" ||
		built.ConnectionOptions.TLS.ServerName != "temporal.internal" || starter.Namespace() != "runtime-v2" {
		t.Fatalf("caller-backed strings drifted: %q / %q / %q / %q",
			built.HostPort, built.Namespace, built.ConnectionOptions.TLS.ServerName, starter.Namespace())
	}
	if err := starter.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeV2ClientOptionsRejectInvalidEndpointTrustAndCertificateBeforeDial(t *testing.T) {
	validRoots, validCertificate := newRuntimeV2ClientPKI(
		t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	valid := RuntimeV2ClientOptions{
		HostPort: "temporal.internal:7233", Namespace: "runtime-v2", ServerName: "temporal.internal",
		RootCAs: validRoots, Certificate: validCertificate,
	}
	_, mismatchKey := newRuntimeV2ClientPKI(
		t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	expiredRoots, expiredCertificate := newRuntimeV2ClientPKI(
		t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	futureRoots, futureCertificate := newRuntimeV2ClientPKI(
		t, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	serverRoots, serverCertificate := newRuntimeV2ClientPKI(
		t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	)
	emptyRoots := x509.NewCertPool()
	mismatched := validCertificate
	mismatched.PrivateKey = mismatchKey.PrivateKey
	validPrivate := validCertificate.PrivateKey.(*ecdsa.PrivateKey)
	foreignPrivate := mismatchKey.PrivateKey.(*ecdsa.PrivateKey)
	inconsistentScalar := validCertificate
	inconsistentScalar.PrivateKey = &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(), X: new(big.Int).Set(validPrivate.PublicKey.X),
			Y: new(big.Int).Set(validPrivate.PublicKey.Y),
		},
		D: new(big.Int).Set(foreignPrivate.D),
	}
	tests := map[string]RuntimeV2ClientOptions{
		"empty host":             withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) { option.HostPort = "" }),
		"default-like host":      withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) { option.HostPort = "localhost" }),
		"URL host":               withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) { option.HostPort = "https://temporal.internal:7233" }),
		"invalid port":           withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) { option.HostPort = "temporal.internal:0" }),
		"empty namespace":        withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) { option.Namespace = "" }),
		"invalid namespace":      withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) { option.Namespace = " invalid " }),
		"empty server name":      withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) { option.ServerName = "" }),
		"wildcard server name":   withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) { option.ServerName = "*.internal" }),
		"nil roots":              withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) { option.RootCAs = nil }),
		"empty roots":            withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) { option.RootCAs = emptyRoots }),
		"missing certificate":    withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) { option.Certificate = tls.Certificate{} }),
		"mismatched private key": withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) { option.Certificate = mismatched }),
		"inconsistent private scalar": withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) {
			option.Certificate = inconsistentScalar
		}),
		"expired certificate": withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) {
			option.RootCAs, option.Certificate = expiredRoots, expiredCertificate
		}),
		"future certificate": withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) {
			option.RootCAs, option.Certificate = futureRoots, futureCertificate
		}),
		"server-only EKU": withRuntimeV2ClientOption(valid, func(option *RuntimeV2ClientOptions) {
			option.RootCAs, option.Certificate = serverRoots, serverCertificate
		}),
	}
	for name, options := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := runtimeV2SDKOptions(options, runtimeV2StarterIdentity); !errors.Is(err, errRuntimeV2ClientRejected) {
				t.Fatalf("runtimeV2SDKOptions() error = %v", err)
			}
			if created, err := DialRuntimeV2StarterClient(context.Background(), options); created != nil ||
				!errors.Is(err, errRuntimeV2ClientRejected) {
				t.Fatalf("DialRuntimeV2StarterClient() = %#v, %v", created, err)
			}
			if created, err := DialRuntimeV2ControlClient(context.Background(), options); created != nil ||
				!errors.Is(err, errRuntimeV2ClientRejected) {
				t.Fatalf("DialRuntimeV2ControlClient() = %#v, %v", created, err)
			}
		})
	}
	if _, err := runtimeV2SDKOptions(valid, "caller-controlled-role"); !errors.Is(err, errRuntimeV2ClientRejected) {
		t.Fatalf("runtimeV2SDKOptions(custom identity) error = %v", err)
	}
	if created, err := DialRuntimeV2StarterClient(nil, valid); created != nil || !errors.Is(err, errRuntimeV2ClientRejected) {
		t.Fatalf("DialRuntimeV2StarterClient(nil) = %#v, %v", created, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if created, err := DialRuntimeV2ControlClient(cancelled, valid); created != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("DialRuntimeV2ControlClient(cancelled) = %#v, %v", created, err)
	}
}

func TestRuntimeV2PublicDialCanonicalizesHostileContextBeforeAnyNetwork(t *testing.T) {
	roots, certificate := newRuntimeV2ClientPKI(
		t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	options := RuntimeV2ClientOptions{
		HostPort: "temporal.invalid:7233", Namespace: "runtime-v2", ServerName: "temporal.invalid",
		RootCAs: roots, Certificate: certificate,
	}
	const canary = "runtime-v2-hostile-context-secret-canary"
	var typedNil *runtimeV2HostileDialContext
	tests := []struct {
		name string
		ctx  context.Context
		want error
	}{
		{name: "nil", ctx: nil, want: errRuntimeV2ClientRejected},
		{name: "typed nil", ctx: typedNil, want: errRuntimeV2ClientRejected},
		{name: "panic", ctx: &runtimeV2HostileDialContext{Context: context.Background(), panicErr: canary}, want: errRuntimeV2ClientRejected},
		{name: "arbitrary", ctx: &runtimeV2HostileDialContext{Context: context.Background(), err: errors.New(canary)}, want: errRuntimeV2ClientRejected},
		{name: "wrapped canceled", ctx: &runtimeV2HostileDialContext{Context: context.Background(), err: fmt.Errorf("%s: %w", canary, context.Canceled)}, want: errRuntimeV2ClientRejected},
		{name: "wrapped deadline", ctx: &runtimeV2HostileDialContext{Context: context.Background(), err: fmt.Errorf("%s: %w", canary, context.DeadlineExceeded)}, want: errRuntimeV2ClientRejected},
		{name: "exact canceled", ctx: &runtimeV2HostileDialContext{Context: context.Background(), err: context.Canceled}, want: context.Canceled},
		{name: "exact deadline", ctx: &runtimeV2HostileDialContext{Context: context.Background(), err: context.DeadlineExceeded}, want: context.DeadlineExceeded},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			for role, dial := range map[string]func(context.Context, RuntimeV2ClientOptions) error{
				"starter": func(ctx context.Context, options RuntimeV2ClientOptions) error {
					created, err := DialRuntimeV2StarterClient(ctx, options)
					if created != nil {
						t.Fatal("hostile context created a Starter client")
					}
					return err
				},
				"control": func(ctx context.Context, options RuntimeV2ClientOptions) error {
					created, err := DialRuntimeV2ControlClient(ctx, options)
					if created != nil {
						t.Fatal("hostile context created a Control client")
					}
					return err
				},
			} {
				t.Run(role, func(t *testing.T) {
					err := dial(testCase.ctx, options)
					if !errors.Is(err, testCase.want) || strings.Contains(fmt.Sprintf("%+v", err), canary) {
						t.Fatalf("Dial(%s) error = %#v, want %v", role, err, testCase.want)
					}
				})
			}
		})
	}
}

func TestRuntimeV2PublicDialUsesRealTLS13MutualAuthentication(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	fixture := newRuntimeV2TemporalMTLSServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	starter, err := DialRuntimeV2StarterClient(ctx, fixture.options)
	if err != nil {
		t.Fatalf("DialRuntimeV2StarterClient() error = %v", err)
	}
	if starter.Namespace() != fixture.options.Namespace {
		t.Fatalf("starter Namespace() = %q", starter.Namespace())
	}
	if err := starter.Close(); err != nil {
		t.Fatalf("starter Close() error = %v", err)
	}
	control, err := DialRuntimeV2ControlClient(ctx, fixture.options)
	if err != nil {
		t.Fatalf("DialRuntimeV2ControlClient() error = %v", err)
	}
	if control.Namespace() != fixture.options.Namespace {
		t.Fatalf("control Namespace() = %q", control.Namespace())
	}
	if err := control.Close(); err != nil {
		t.Fatalf("control Close() error = %v", err)
	}
	if fixture.service.calls.Load() < 2 || fixture.service.invalidPeer.Load() {
		t.Fatalf("GetSystemInfo calls/invalid peer = %d/%t", fixture.service.calls.Load(), fixture.service.invalidPeer.Load())
	}
	if fixture.service.clusterCalls.Load() < 2 || fixture.service.namespaceCalls.Load() < 2 {
		t.Fatalf("attestation calls = cluster:%d namespace:%d",
			fixture.service.clusterCalls.Load(), fixture.service.namespaceCalls.Load())
	}

	missingCertificate := fixture.options
	missingCertificate.Certificate = tls.Certificate{}
	if created, err := DialRuntimeV2StarterClient(context.Background(), missingCertificate); created != nil ||
		!errors.Is(err, errRuntimeV2ClientRejected) {
		t.Fatalf("DialRuntimeV2StarterClient(missing certificate) = %#v, %v", created, err)
	}
	foreignRoots, _ := newRuntimeV2ClientPKI(
		t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	foreignClientAuthority := newRuntimeV2TestAuthority(t)
	foreignClientCertificate := foreignClientAuthority.issue(
		t, "foreign-runtime-v2-client", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
	)
	for name, options := range map[string]RuntimeV2ClientOptions{
		"wrong root": withRuntimeV2ClientOption(fixture.options, func(option *RuntimeV2ClientOptions) {
			option.RootCAs = foreignRoots
		}),
		"wrong server name": withRuntimeV2ClientOption(fixture.options, func(option *RuntimeV2ClientOptions) {
			option.ServerName = "foreign.internal"
		}),
		"wrong client CA": withRuntimeV2ClientOption(fixture.options, func(option *RuntimeV2ClientOptions) {
			option.Certificate = foreignClientCertificate
		}),
	} {
		t.Run(name, func(t *testing.T) {
			attempt, stop := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer stop()
			if created, err := DialRuntimeV2ControlClient(attempt, options); created != nil ||
				!errors.Is(err, errRuntimeV2ClientRejected) {
				t.Fatalf("DialRuntimeV2ControlClient() = %#v, %v", created, err)
			}
		})
	}
}

func TestRuntimeV2ProductionConnectionBindingUsesServerDeploymentIdentity(t *testing.T) {
	fixture := newRuntimeV2TemporalMTLSServer(t)
	dialContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	starter, err := DialRuntimeV2StarterClient(dialContext, fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	defer starter.Close()

	// Model one DNS/LB/TLS identity routing the second role dial to another
	// Temporal deployment. Configuration-only binding cannot detect this.
	fixture.service.clusterID.Store("00000000-0000-4000-8000-000000000002")
	control, err := DialRuntimeV2ControlClient(dialContext, fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if starter.sameTemporalConnection(control) {
		t.Fatal("one endpoint and trust profile routed to distinct server deployments was accepted")
	}
}

func TestRuntimeV2ProductionConnectionBindingUsesServerNamespaceIdentity(t *testing.T) {
	fixture := newRuntimeV2TemporalMTLSServer(t)
	dialContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	starter, err := DialRuntimeV2StarterClient(dialContext, fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	defer starter.Close()
	fixture.service.namespaceID.Store("00000000-0000-4000-8000-000000000012")
	control, err := DialRuntimeV2ControlClient(dialContext, fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if starter.sameTemporalConnection(control) {
		t.Fatal("same cluster with a recreated same-name namespace was accepted")
	}
}

func TestRuntimeV2ServerAttestationRejectsMalformedAndUnavailableIdentity(t *testing.T) {
	roots, certificate := newRuntimeV2ClientPKI(
		t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	sdkOptions, err := runtimeV2SDKOptions(RuntimeV2ClientOptions{
		HostPort: "temporal.internal:7233", Namespace: "runtime-v2", ServerName: "temporal.internal",
		RootCAs: roots, Certificate: certificate,
	}, runtimeV2ControlIdentity)
	if err != nil {
		t.Fatal(err)
	}
	baseBinding, err := newRuntimeV2ConnectionBinding(sdkOptions)
	if err != nil {
		t.Fatal(err)
	}
	validService := func() *runtimeV2AttestationService {
		return &runtimeV2AttestationService{
			cluster: &workflowservicepb.GetClusterInfoResponse{
				ClusterId: "00000000-0000-4000-8000-000000000001", ClusterName: "runtime-v2-cluster",
			},
			namespace: &workflowservicepb.DescribeNamespaceResponse{NamespaceInfo: &namespacepb.NamespaceInfo{
				Name: "runtime-v2", Id: "00000000-0000-4000-8000-000000000010",
				State: enumspb.NAMESPACE_STATE_REGISTERED,
			}},
		}
	}
	mutations := map[string]func(*runtimeV2AttestationService){
		"cluster RPC error": func(service *runtimeV2AttestationService) {
			service.clusterErr = errors.New("ATTESTATION-SECRET-CANARY")
		},
		"nil cluster": func(service *runtimeV2AttestationService) { service.cluster = nil },
		"zero cluster ID": func(service *runtimeV2AttestationService) {
			service.cluster.ClusterId = "00000000-0000-0000-0000-000000000000"
		},
		"noncanonical cluster ID": func(service *runtimeV2AttestationService) {
			service.cluster.ClusterId = "00000000-0000-4000-8000-00000000000A"
		},
		"control cluster name": func(service *runtimeV2AttestationService) {
			service.cluster.ClusterName = "runtime-v2\u202ecluster"
		},
		"namespace RPC error": func(service *runtimeV2AttestationService) {
			service.namespaceErr = errors.New("ATTESTATION-SECRET-CANARY")
		},
		"nil namespace": func(service *runtimeV2AttestationService) { service.namespace = nil },
		"nil namespace info": func(service *runtimeV2AttestationService) {
			service.namespace.NamespaceInfo = nil
		},
		"mismatched namespace": func(service *runtimeV2AttestationService) {
			service.namespace.NamespaceInfo.Name = "foreign"
		},
		"deprecated namespace": func(service *runtimeV2AttestationService) {
			service.namespace.NamespaceInfo.State = enumspb.NAMESPACE_STATE_DEPRECATED
		},
		"zero namespace ID": func(service *runtimeV2AttestationService) {
			service.namespace.NamespaceInfo.Id = "00000000-0000-0000-0000-000000000000"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			service := validService()
			mutate(service)
			created, attestErr := attestRuntimeV2Connection(
				context.Background(), &runtimeV2AttestationSDK{service: service}, baseBinding,
			)
			if created != nil || !errors.Is(attestErr, errRuntimeV2ClientRejected) ||
				strings.Contains(fmt.Sprintf("%+v", attestErr), "ATTESTATION-SECRET-CANARY") {
				t.Fatalf("attestRuntimeV2Connection() = %#v, %v", created, attestErr)
			}
		})
	}
	attested, err := attestRuntimeV2Connection(
		context.Background(), &runtimeV2AttestationSDK{service: validService()}, baseBinding,
	)
	if err != nil || !attested.valid() {
		t.Fatalf("attestRuntimeV2Connection(valid) = %#v, %v", attested, err)
	}
}

func TestRuntimeV2ProductionConnectionBindingRejectsRoleAssemblyDrift(t *testing.T) {
	fixture := newRuntimeV2TemporalMTLSServer(t)
	dialContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	starter, err := DialRuntimeV2StarterClient(dialContext, fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	sameConnectionOptions := fixture.options
	sameConnectionOptions.RootCAs = fixture.options.RootCAs.Clone()
	sameConnectionOptions.Certificate = fixture.alternateClientCertificate
	control, err := DialRuntimeV2ControlClient(dialContext, sameConnectionOptions)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(
		fixture.options.Certificate.Certificate[0],
		sameConnectionOptions.Certificate.Certificate[0],
	) {
		t.Fatal("test fixture did not use distinct role certificates")
	}
	if !starter.sameTemporalConnection(control) {
		t.Fatal("same endpoint/root with distinct role certificates was rejected")
	}

	foreignAuthority := newRuntimeV2TestAuthority(t)
	rootDriftOptions := sameConnectionOptions
	rootDriftOptions.RootCAs = sameConnectionOptions.RootCAs.Clone()
	rootDriftOptions.RootCAs.AddCert(foreignAuthority.certificate)
	hostDriftOptions := sameConnectionOptions
	hostDriftOptions.HostPort = fixture.alternateHostPort
	serverNameDriftOptions := sameConnectionOptions
	serverNameDriftOptions.ServerName = "temporal-alt.internal"
	namespaceDriftOptions := sameConnectionOptions
	namespaceDriftOptions.Namespace = "runtime-v2-other"
	for name, options := range map[string]RuntimeV2ClientOptions{
		"root":        rootDriftOptions,
		"host":        hostDriftOptions,
		"server name": serverNameDriftOptions,
		"namespace":   namespaceDriftOptions,
	} {
		t.Run(name+" drift", func(t *testing.T) {
			drifted, err := DialRuntimeV2ControlClient(dialContext, options)
			if err != nil {
				t.Fatalf("DialRuntimeV2ControlClient() error = %v", err)
			}
			defer drifted.Close()
			if starter.sameTemporalConnection(drifted) {
				t.Fatal("drifted production connection was accepted")
			}
		})
	}

	foreignFixture := newRuntimeV2TemporalMTLSServer(t)
	foreignControl, err := DialRuntimeV2ControlClient(dialContext, foreignFixture.options)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignControl.Close()
	if starter.sameTemporalConnection(foreignControl) {
		t.Fatal("independent mTLS endpoints with one namespace were accepted")
	}

	testStarter, err := newRuntimeV2StarterClient(&recordingRuntimeV2StarterTransport{}, "runtime-v2")
	if err != nil {
		t.Fatal(err)
	}
	testControl, err := newRuntimeV2ControlClient(&recordingRuntimeV2SDKClient{}, "runtime-v2")
	if err != nil {
		t.Fatal(err)
	}
	if testStarter.sameTemporalConnection(testControl) {
		t.Fatal("test-only role clients without production bindings were accepted")
	}
	starterCopy := *starter
	controlCopy := *control
	if starterCopy.sameTemporalConnection(control) || starter.sameTemporalConnection(&controlCopy) ||
		starter.sameTemporalConnection(nil) || (*RuntimeV2StarterClient)(nil).sameTemporalConnection(control) ||
		(&RuntimeV2StarterClient{}).sameTemporalConnection(control) {
		t.Fatal("copy, zero, or nil role client passed connection binding")
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	if starter.sameTemporalConnection(control) {
		t.Fatal("closed role client passed connection binding")
	}
	if err := starter.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeV2ConnectionBindingComparesRootCertificatesNotSubjects(t *testing.T) {
	firstAuthority := newRuntimeV2TestAuthority(t)
	secondAuthority := newRuntimeV2TestAuthority(t)
	if !bytes.Equal(firstAuthority.roots.Subjects()[0], secondAuthority.roots.Subjects()[0]) ||
		firstAuthority.roots.Equal(secondAuthority.roots) {
		t.Fatal("test authorities must have equal subjects but different certificates")
	}
	newBinding := func(roots *x509.CertPool, identity string) *runtimeV2ConnectionBinding {
		t.Helper()
		binding, err := newRuntimeV2ConnectionBinding(client.Options{
			HostPort: "temporal.internal:7233", Namespace: "runtime-v2", Identity: identity,
			ConnectionOptions: client.ConnectionOptions{TLS: &tls.Config{
				ServerName: "temporal.internal", RootCAs: roots,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := runtimeV2DeploymentProof(
			"00000000-0000-4000-8000-000000000001",
			"runtime-v2-test-cluster",
			"runtime-v2",
			"00000000-0000-4000-8000-000000000010",
		)
		if err != nil {
			t.Fatal(err)
		}
		binding.deploymentProof = proof
		binding.attested = true
		return binding
	}
	first := newBinding(firstAuthority.roots, runtimeV2StarterIdentity)
	second := newBinding(secondAuthority.roots, runtimeV2ControlIdentity)
	if first.same(second) {
		t.Fatal("root pools with matching subjects but distinct certificates were accepted")
	}
}

func TestBoundRuntimeV2TemporalRolesSerializesAssemblyAgainstClose(t *testing.T) {
	controlClient, activities, manifest, registry := newRuntimeV2ControlWorkerFixture(t, "default")
	starterTransport := &recordingRuntimeV2StarterTransport{}
	starterClient, err := newRuntimeV2StarterClient(starterTransport, "default")
	if err != nil {
		t.Fatal(err)
	}
	authority := newRuntimeV2TestAuthority(t)
	proof, err := runtimeV2DeploymentProof(
		"00000000-0000-4000-8000-000000000020",
		"runtime-v2-assembly-cluster",
		"default",
		"00000000-0000-4000-8000-000000000021",
	)
	if err != nil {
		t.Fatal(err)
	}
	newBinding := func() *runtimeV2ConnectionBinding {
		return &runtimeV2ConnectionBinding{
			hostPort: "temporal.internal:7233", namespace: "default", serverName: "temporal.internal",
			rootCAs: authority.roots.Clone(), deploymentProof: proof, attested: true, seal: runtimeV2ConnectionSeal,
		}
	}
	starterClient.connection = newBinding()
	controlClient.connection = newBinding()

	entered := make(chan struct{})
	release := make(chan struct{})
	runtime := &captureRuntimeV2ControlWorker{}
	type assemblyResult struct {
		starter *RuntimeV2Starter
		worker  *RuntimeV2ControlWorker
		err     error
	}
	assembled := make(chan assemblyResult, 1)
	go func() {
		starter, controlWorker, createErr := newBoundRuntimeV2TemporalRoles(
			starterClient,
			controlClient,
			activities,
			manifest,
			registry,
			inputBundleDigestForRuntimeV2Test,
			func(client.Client, string, worker.Options) runtimeV2ControlWorkerRuntime {
				close(entered)
				<-release
				return runtime
			},
		)
		assembled <- assemblyResult{starter: starter, worker: controlWorker, err: createErr}
	}()
	<-entered
	starterClosed := make(chan error, 1)
	controlClosed := make(chan error, 1)
	go func() { starterClosed <- starterClient.Close() }()
	go func() { controlClosed <- controlClient.Close() }()
	for role, completed := range map[string]<-chan error{
		"starter": starterClosed,
		"control": controlClosed,
	} {
		select {
		case closeErr := <-completed:
			t.Fatalf("%s Close interleaved with assembly: %v", role, closeErr)
		case <-time.After(100 * time.Millisecond):
		}
	}
	close(release)
	result := <-assembled
	if result.err != nil || result.starter == nil || result.worker == nil {
		t.Fatalf("newBoundRuntimeV2TemporalRoles() = %#v, %#v, %v", result.starter, result.worker, result.err)
	}
	if err := <-starterClosed; err != nil {
		t.Fatalf("starter Close() error = %v", err)
	}
	if err := <-controlClosed; err != nil {
		t.Fatalf("control Close() error = %v", err)
	}
	if starterTransport.closes.Load() != 1 {
		t.Fatalf("starter transport Close calls = %d", starterTransport.closes.Load())
	}
	if err := result.worker.Stop(); err != nil {
		t.Fatalf("assembled Worker Stop() error = %v", err)
	}
}

func TestRuntimeV2RoleClientsAreDistinctSealedAndCloseExactlyOnce(t *testing.T) {
	starterTransport := &recordingRuntimeV2StarterTransport{}
	starter, err := newRuntimeV2StarterClient(starterTransport, "runtime-v2-test")
	if err != nil {
		t.Fatalf("newRuntimeV2StarterClient() error = %v", err)
	}
	controlSDK := &recordingRuntimeV2SDKClient{}
	control, err := newRuntimeV2ControlClient(controlSDK, "runtime-v2-test")
	if err != nil {
		t.Fatalf("newRuntimeV2ControlClient() error = %v", err)
	}
	if reflect.TypeOf(starter) == reflect.TypeOf(control) || !starter.structurallyValid() ||
		!starter.validForStarter() || !starter.valid() || !control.structurallyValid() || !control.valid() {
		t.Fatal("role clients are not distinct valid sealed values")
	}
	if starter.Namespace() != "runtime-v2-test" || starter.namespaceValue() != "runtime-v2-test" ||
		control.Namespace() != "runtime-v2-test" || control.namespaceValue() != "runtime-v2-test" ||
		starter.starterTransportValue() == nil || control.sdkValue() == nil {
		t.Fatal("valid role client did not expose its narrow same-package capability")
	}

	starterCopy := *starter
	controlCopy := *control
	if starterCopy.structurallyValid() || starterCopy.valid() || starterCopy.Namespace() != "" ||
		starterCopy.starterTransportValue() != nil || controlCopy.structurallyValid() || controlCopy.valid() ||
		controlCopy.Namespace() != "" || controlCopy.sdkValue() != nil {
		t.Fatal("copied role client remained usable")
	}
	if err := starterCopy.Close(); !errors.Is(err, errRuntimeV2ClientRejected) {
		t.Fatalf("copied starter Close() error = %v", err)
	}
	if err := controlCopy.Close(); !errors.Is(err, errRuntimeV2ClientRejected) {
		t.Fatalf("copied control Close() error = %v", err)
	}

	closeConcurrently(t, starter.Close)
	closeConcurrently(t, control.Close)
	if got := starterTransport.closes.Load(); got != 1 {
		t.Fatalf("starter transport Close calls = %d", got)
	}
	if got := controlSDK.closes.Load(); got != 1 {
		t.Fatalf("control SDK Close calls = %d", got)
	}
	if starter.valid() || starter.validForStarter() || !starter.structurallyValid() || starter.Namespace() != "" ||
		starter.starterTransportValue() != nil || control.valid() || !control.structurallyValid() ||
		control.Namespace() != "" || control.sdkValue() != nil {
		t.Fatal("closed role client remained usable or lost structural cleanup authority")
	}
	if err := starter.Close(); err != nil {
		t.Fatalf("second starter Close() error = %v", err)
	}
	if err := control.Close(); err != nil {
		t.Fatalf("second control Close() error = %v", err)
	}
}

func TestRuntimeV2RoleClientsRejectNilZeroTypedNilAndInvalidNamespace(t *testing.T) {
	var typedNilStarter *recordingRuntimeV2StarterTransport
	var typedNilSDK *recordingRuntimeV2SDKClient
	for name, create := range map[string]func() error{
		"nil starter":       func() error { _, err := newRuntimeV2StarterClient(nil, "default"); return err },
		"typed nil starter": func() error { _, err := newRuntimeV2StarterClient(typedNilStarter, "default"); return err },
		"invalid starter namespace": func() error {
			_, err := newRuntimeV2StarterClient(&recordingRuntimeV2StarterTransport{}, " invalid ")
			return err
		},
		"nil control":       func() error { _, err := newRuntimeV2ControlClient(nil, "default"); return err },
		"typed nil control": func() error { _, err := newRuntimeV2ControlClient(typedNilSDK, "default"); return err },
		"invalid control namespace": func() error {
			_, err := newRuntimeV2ControlClient(&recordingRuntimeV2SDKClient{}, " invalid ")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := create(); !errors.Is(err, errRuntimeV2ClientRejected) {
				t.Fatalf("constructor error = %v", err)
			}
		})
	}

	invalidStarters := []*RuntimeV2StarterClient{nil, {}}
	for _, invalid := range invalidStarters {
		if invalid.Namespace() != "" || invalid.valid() || invalid.starterTransportValue() != nil {
			t.Fatal("nil/zero starter remained usable")
		}
		if err := invalid.Close(); !errors.Is(err, errRuntimeV2ClientRejected) {
			t.Fatalf("nil/zero starter Close() error = %v", err)
		}
	}
	invalidControls := []*RuntimeV2ControlClient{nil, {}}
	for _, invalid := range invalidControls {
		if invalid.Namespace() != "" || invalid.valid() || invalid.sdkValue() != nil {
			t.Fatal("nil/zero control remained usable")
		}
		if err := invalid.Close(); !errors.Is(err, errRuntimeV2ClientRejected) {
			t.Fatalf("nil/zero control Close() error = %v", err)
		}
	}
}

func TestRuntimeV2SDKStarterHistoryPreservesCanonicalContextErrors(t *testing.T) {
	var typedNil *runtimeV2HostileDialContext
	tests := []struct {
		name     string
		ctx      context.Context
		iterator client.HistoryEventIterator
		want     error
	}{
		{
			name: "canceled before empty iterator", ctx: canceledRuntimeV2Context(),
			iterator: &runtimeV2HistoryIterator{}, want: context.Canceled,
		},
		{
			name: "deadline before next error", ctx: expiredRuntimeV2Context(t),
			iterator: &runtimeV2HistoryIterator{hasNext: true, err: errors.New("remote canary")},
			want:     context.DeadlineExceeded,
		},
		{
			name: "live empty iterator", ctx: context.Background(),
			iterator: &runtimeV2HistoryIterator{}, want: errRuntimeV2ClientRejected,
		},
		{
			name: "live next error", ctx: context.Background(),
			iterator: &runtimeV2HistoryIterator{hasNext: true, err: errors.New("remote canary")},
			want:     errRuntimeV2ClientRejected,
		},
		{
			name: "nil context", ctx: nil,
			iterator: &runtimeV2HistoryIterator{}, want: errRuntimeV2ClientRejected,
		},
		{
			name: "typed nil context", ctx: typedNil,
			iterator: &runtimeV2HistoryIterator{}, want: errRuntimeV2ClientRejected,
		},
		{
			name:     "panicking context",
			ctx:      &runtimeV2HostileDialContext{Context: context.Background(), panicErr: "remote canary"},
			iterator: &runtimeV2HistoryIterator{}, want: errRuntimeV2ClientRejected,
		},
		{
			name:     "arbitrary context error",
			ctx:      &runtimeV2HostileDialContext{Context: context.Background(), err: errors.New("remote canary")},
			iterator: &runtimeV2HistoryIterator{}, want: errRuntimeV2ClientRejected,
		},
		{
			name: "wrapped context error",
			ctx: &runtimeV2HostileDialContext{
				Context: context.Background(), err: fmt.Errorf("remote canary: %w", context.Canceled),
			},
			iterator: &runtimeV2HistoryIterator{}, want: errRuntimeV2ClientRejected,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			transport := &runtimeV2SDKStarterTransport{Client: &runtimeV2HistorySDKClient{iterator: testCase.iterator}}
			event, err := transport.FirstWorkflowHistoryEvent(testCase.ctx, "workflow", "run")
			if event != nil || !errors.Is(err, testCase.want) {
				t.Fatalf("FirstWorkflowHistoryEvent() = %#v, %v; want %v", event, err, testCase.want)
			}
		})
	}
}

func TestRuntimeV2RoleClientsAlwaysRedactAndRejectJSON(t *testing.T) {
	const canary = "runtime-v2-client-secret-canary"
	starter, err := newRuntimeV2StarterClient(&recordingRuntimeV2StarterTransport{canary: canary}, "runtime-v2")
	if err != nil {
		t.Fatal(err)
	}
	control, err := newRuntimeV2ControlClient(&recordingRuntimeV2SDKClient{canary: canary}, "runtime-v2")
	if err != nil {
		t.Fatal(err)
	}
	starterCopy := *starter
	controlCopy := *control
	if err := starter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	values := []interface{}{
		starter, *starter, starterCopy, RuntimeV2StarterClient{},
		control, *control, controlCopy, RuntimeV2ControlClient{},
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			encoded := fmt.Sprintf(format, value)
			if strings.Contains(encoded, canary) || strings.Contains(encoded, "transport") ||
				strings.Contains(encoded, "sdk:") || strings.Contains(encoded, "runtime-v2") {
				t.Fatalf("fmt.Sprintf(%q, %T) leaked internals: %q", format, value, encoded)
			}
		}
		if encoded, err := json.Marshal(value); encoded != nil || !errors.Is(err, errRuntimeV2ClientRejected) {
			t.Fatalf("json.Marshal(%T) = %q, %v", value, encoded, err)
		}
	}
	if err := json.Unmarshal([]byte(`{}`), &RuntimeV2StarterClient{}); !errors.Is(err, errRuntimeV2ClientRejected) {
		t.Fatalf("starter UnmarshalJSON error = %v", err)
	}
	if err := json.Unmarshal([]byte(`{}`), &RuntimeV2ControlClient{}); !errors.Is(err, errRuntimeV2ClientRejected) {
		t.Fatalf("control UnmarshalJSON error = %v", err)
	}
}

func TestRuntimeV2ClientOptionsAlwaysRedactAndRejectJSON(t *testing.T) {
	roots, certificate := newRuntimeV2ClientPKI(
		t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	options := RuntimeV2ClientOptions{
		HostPort: "temporal-secret.internal:7233", Namespace: "runtime-secret",
		ServerName: "temporal-secret.internal", RootCAs: roots, Certificate: certificate,
	}
	for _, value := range []interface{}{options, &options, RuntimeV2ClientOptions{}, &RuntimeV2ClientOptions{}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			encoded := fmt.Sprintf(format, value)
			if strings.Contains(encoded, "temporal-secret") || strings.Contains(encoded, "runtime-secret") ||
				strings.Contains(encoded, "PrivateKey") || strings.Contains(encoded, "Certificate") {
				t.Fatalf("fmt.Sprintf(%q, %T) leaked options: %q", format, value, encoded)
			}
		}
		if encoded, err := json.Marshal(value); encoded != nil || !errors.Is(err, errRuntimeV2ClientRejected) {
			t.Fatalf("json.Marshal(%T) = %q, %v", value, encoded, err)
		}
	}
	if err := json.Unmarshal([]byte(`{}`), &RuntimeV2ClientOptions{}); !errors.Is(err, errRuntimeV2ClientRejected) {
		t.Fatalf("options UnmarshalJSON error = %v", err)
	}
}

func TestRuntimeV2RoleClientsRemainTerminalWhenUnderlyingClosePanics(t *testing.T) {
	starterTransport := &recordingRuntimeV2StarterTransport{panicClose: true}
	starter, err := newRuntimeV2StarterClient(starterTransport, "default")
	if err != nil {
		t.Fatal(err)
	}
	controlSDK := &recordingRuntimeV2SDKClient{panicClose: true}
	control, err := newRuntimeV2ControlClient(controlSDK, "default")
	if err != nil {
		t.Fatal(err)
	}
	for name, closeFn := range map[string]func() error{"starter": starter.Close, "control": control.Close} {
		t.Run(name, func(t *testing.T) {
			if err := closeFn(); !errors.Is(err, errRuntimeV2ClientRejected) {
				t.Fatalf("first Close() error = %v", err)
			}
			if err := closeFn(); !errors.Is(err, errRuntimeV2ClientRejected) {
				t.Fatalf("second Close() error = %v", err)
			}
		})
	}
	if starterTransport.closes.Load() != 1 || controlSDK.closes.Load() != 1 ||
		starter.valid() || control.valid() {
		t.Fatalf("panic close calls/valid = %d/%d/%t/%t",
			starterTransport.closes.Load(), controlSDK.closes.Load(), starter.valid(), control.valid())
	}
}

func closeConcurrently(t *testing.T, closeFn func() error) {
	t.Helper()
	const goroutines = 32
	start := make(chan struct{})
	errorsChannel := make(chan error, goroutines)
	var group sync.WaitGroup
	for range goroutines {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			errorsChannel <- closeFn()
		}()
	}
	close(start)
	group.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent Close() error = %v", err)
		}
	}
}

type recordingRuntimeV2StarterTransport struct {
	closes     atomic.Int32
	canary     string
	panicClose bool
}

func (*recordingRuntimeV2StarterTransport) ExecuteWorkflow(
	context.Context,
	client.StartWorkflowOptions,
	interface{},
	...interface{},
) (client.WorkflowRun, error) {
	return nil, nil
}

func (*recordingRuntimeV2StarterTransport) DescribeWorkflowExecution(
	context.Context,
	string,
	string,
) (*workflowservicepb.DescribeWorkflowExecutionResponse, error) {
	return nil, nil
}

func (*recordingRuntimeV2StarterTransport) FirstWorkflowHistoryEvent(
	context.Context,
	string,
	string,
) (*historypb.HistoryEvent, error) {
	return nil, nil
}

func (transport *recordingRuntimeV2StarterTransport) Close() {
	transport.closes.Add(1)
	if transport.panicClose {
		panic("runtime-v2-starter-close-canary")
	}
}

type recordingRuntimeV2SDKClient struct {
	client.Client
	closes     atomic.Int32
	canary     string
	panicClose bool
}

type runtimeV2AttestationSDK struct {
	client.Client
	service workflowservicepb.WorkflowServiceClient
}

func (sdk *runtimeV2AttestationSDK) WorkflowService() workflowservicepb.WorkflowServiceClient {
	return sdk.service
}

type runtimeV2AttestationService struct {
	workflowservicepb.WorkflowServiceClient
	cluster      *workflowservicepb.GetClusterInfoResponse
	clusterErr   error
	namespace    *workflowservicepb.DescribeNamespaceResponse
	namespaceErr error
}

func (service *runtimeV2AttestationService) GetClusterInfo(
	context.Context,
	*workflowservicepb.GetClusterInfoRequest,
	...grpc.CallOption,
) (*workflowservicepb.GetClusterInfoResponse, error) {
	return service.cluster, service.clusterErr
}

func (service *runtimeV2AttestationService) DescribeNamespace(
	context.Context,
	*workflowservicepb.DescribeNamespaceRequest,
	...grpc.CallOption,
) (*workflowservicepb.DescribeNamespaceResponse, error) {
	return service.namespace, service.namespaceErr
}

type runtimeV2HistorySDKClient struct {
	client.Client
	iterator client.HistoryEventIterator
}

func (sdk *runtimeV2HistorySDKClient) GetWorkflowHistory(
	context.Context,
	string,
	string,
	bool,
	enumspb.HistoryEventFilterType,
) client.HistoryEventIterator {
	return sdk.iterator
}

type runtimeV2HistoryIterator struct {
	hasNext bool
	event   *historypb.HistoryEvent
	err     error
}

func (iterator *runtimeV2HistoryIterator) HasNext() bool { return iterator.hasNext }

func (iterator *runtimeV2HistoryIterator) Next() (*historypb.HistoryEvent, error) {
	return iterator.event, iterator.err
}

func canceledRuntimeV2Context() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func expiredRuntimeV2Context(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	t.Cleanup(cancel)
	return ctx
}

func (sdk *recordingRuntimeV2SDKClient) Close() {
	sdk.closes.Add(1)
	if sdk.panicClose {
		panic("runtime-v2-control-close-canary")
	}
}

func withRuntimeV2ClientOption(
	base RuntimeV2ClientOptions,
	change func(*RuntimeV2ClientOptions),
) RuntimeV2ClientOptions {
	change(&base)
	return base
}

func newRuntimeV2ClientPKI(
	t *testing.T,
	notBefore time.Time,
	notAfter time.Time,
	extendedKeyUsage []x509.ExtKeyUsage,
) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	rootSerial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial, Subject: pkix.Name{CommonName: "runtime-v2-test-root"},
		NotBefore: notBefore.Add(-time.Hour), NotAfter: notAfter.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafSerial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial, Subject: pkix.Name{CommonName: "runtime-v2-test-client"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: extendedKeyUsage, BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return roots, tls.Certificate{
		Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey, Leaf: leaf,
	}
}

type runtimeV2TemporalMTLSFixture struct {
	options                    RuntimeV2ClientOptions
	alternateClientCertificate tls.Certificate
	alternateHostPort          string
	service                    *runtimeV2SystemInfoService
}

type runtimeV2SystemInfoService struct {
	workflowservicepb.UnimplementedWorkflowServiceServer
	calls          atomic.Int32
	clusterCalls   atomic.Int32
	namespaceCalls atomic.Int32
	invalidPeer    atomic.Bool
	clusterID      atomic.Value
	namespaceID    atomic.Value
}

func (service *runtimeV2SystemInfoService) GetSystemInfo(
	ctx context.Context,
	_ *workflowservicepb.GetSystemInfoRequest,
) (*workflowservicepb.GetSystemInfoResponse, error) {
	service.calls.Add(1)
	peerInfo, found := peer.FromContext(ctx)
	tlsInfo, tlsFound := credentials.TLSInfo{}, false
	if found && peerInfo.AuthInfo != nil {
		tlsInfo, tlsFound = peerInfo.AuthInfo.(credentials.TLSInfo)
	}
	if !tlsFound || tlsInfo.State.Version != tls.VersionTLS13 ||
		len(tlsInfo.State.PeerCertificates) == 0 || len(tlsInfo.State.VerifiedChains) == 0 ||
		tlsInfo.State.NegotiatedProtocol != "h2" {
		service.invalidPeer.Store(true)
		return nil, errRuntimeV2ClientRejected
	}
	return &workflowservicepb.GetSystemInfoResponse{
		ServerVersion: "runtime-v2-test",
		Capabilities:  &workflowservicepb.GetSystemInfoResponse_Capabilities{},
	}, nil
}

func (service *runtimeV2SystemInfoService) GetClusterInfo(
	context.Context,
	*workflowservicepb.GetClusterInfoRequest,
) (*workflowservicepb.GetClusterInfoResponse, error) {
	service.clusterCalls.Add(1)
	clusterID, _ := service.clusterID.Load().(string)
	return &workflowservicepb.GetClusterInfoResponse{
		ClusterId: clusterID, ClusterName: "runtime-v2-test-cluster",
	}, nil
}

func (service *runtimeV2SystemInfoService) DescribeNamespace(
	_ context.Context,
	request *workflowservicepb.DescribeNamespaceRequest,
) (*workflowservicepb.DescribeNamespaceResponse, error) {
	service.namespaceCalls.Add(1)
	namespaceID, _ := service.namespaceID.Load().(string)
	if request.GetNamespace() != "runtime-v2" {
		namespaceID = "00000000-0000-4000-8000-000000000011"
	}
	return &workflowservicepb.DescribeNamespaceResponse{NamespaceInfo: &namespacepb.NamespaceInfo{
		Name: request.GetNamespace(), Id: namespaceID, State: enumspb.NAMESPACE_STATE_REGISTERED,
	}}, nil
}

func newRuntimeV2TemporalMTLSServer(t *testing.T) runtimeV2TemporalMTLSFixture {
	t.Helper()
	authority := newRuntimeV2TestAuthority(t)
	clientCertificate := authority.issue(
		t, "runtime-v2-client", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
	)
	alternateClientCertificate := authority.issue(
		t, "runtime-v2-control-client", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
	)
	serverCertificate := authority.issue(
		t, "temporal.internal", []string{"temporal.internal", "temporal-alt.internal"},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
	)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate}, NextProtos: []string{"h2"},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: authority.roots.Clone(),
	})))
	alternateListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	service := &runtimeV2SystemInfoService{}
	service.clusterID.Store("00000000-0000-4000-8000-000000000001")
	service.namespaceID.Store("00000000-0000-4000-8000-000000000010")
	workflowservicepb.RegisterWorkflowServiceServer(server, service)
	go func() {
		_ = server.Serve(listener)
	}()
	go func() {
		_ = server.Serve(alternateListener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		_ = alternateListener.Close()
	})
	return runtimeV2TemporalMTLSFixture{
		options: RuntimeV2ClientOptions{
			HostPort: listener.Addr().String(), Namespace: "runtime-v2", ServerName: "temporal.internal",
			RootCAs: authority.roots.Clone(), Certificate: clientCertificate,
		},
		alternateClientCertificate: alternateClientCertificate,
		alternateHostPort:          alternateListener.Addr().String(),
		service:                    service,
	}
}

type runtimeV2TestAuthority struct {
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey
	der         []byte
	roots       *x509.CertPool
}

type runtimeV2HostileDialContext struct {
	context.Context
	err      error
	panicErr string
}

func (ctx *runtimeV2HostileDialContext) Err() error {
	if ctx.panicErr != "" {
		panic(ctx.panicErr)
	}
	return ctx.err
}

func newRuntimeV2TestAuthority(t *testing.T) runtimeV2TestAuthority {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: runtimeV2TestSerial(t), Subject: pkix.Name{CommonName: "runtime-v2-live-root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return runtimeV2TestAuthority{certificate: certificate, privateKey: privateKey, der: der, roots: roots}
}

func (authority runtimeV2TestAuthority) issue(
	t *testing.T,
	commonName string,
	dnsNames []string,
	extendedKeyUsage []x509.ExtKeyUsage,
	notBefore time.Time,
	notAfter time.Time,
) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: runtimeV2TestSerial(t), Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames,
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: extendedKeyUsage, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, authority.certificate, &privateKey.PublicKey, authority.privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, authority.der}, PrivateKey: privateKey, Leaf: leaf,
	}
}

func runtimeV2TestSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}
