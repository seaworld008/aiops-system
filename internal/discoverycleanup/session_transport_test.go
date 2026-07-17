package discoverycleanup_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverycleanup"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

const (
	transportTenantID   = "10000000-0000-4000-8000-000000000001"
	transportWorkspace  = "20000000-0000-4000-8000-000000000002"
	transportRunID      = "30000000-0000-4000-8000-000000000003"
	transportRunID2     = "30000000-0000-4000-8000-000000000004"
	transportAttemptID  = "40000000-0000-4000-8000-000000000004"
	transportAttemptID2 = "40000000-0000-4000-8000-000000000005"
	transportDigest     = "1111111111111111111111111111111111111111111111111111111111111111"
	transportDigest2    = "2222222222222222222222222222222222222222222222222222222222222222"

	sessionOpenPath   = "/discovery-cleanup/v1/session:open-or-recover"
	sessionRevokePath = "/discovery-cleanup/v1/session:revoke"
)

func TestSessionTransportRecoveryResponseLossAndChangedTuple(t *testing.T) {
	fixture := newSessionTransportAuthorityFixture(t)
	clientA := fixture.newClient(t, "worker-a")
	clientB := fixture.newClient(t, "worker-b")
	t.Cleanup(clientA.Destroy)
	t.Cleanup(clientB.Destroy)

	request := transportOpenRequest()
	fixture.dropNextOpenResponse()
	opened, err := clientA.OpenOrRecover(t.Context(), request)
	if err != nil || opened == nil {
		t.Fatalf("OpenOrRecover(initial) = %#v,%v", opened, err)
	}
	initial, err := opened.Initial()
	if err != nil || !initial {
		t.Fatalf("Initial(initial lease) = %t,%v", initial, err)
	}

	recovered, err := clientB.OpenOrRecover(t.Context(), request)
	if err != nil || recovered == nil {
		t.Fatalf("OpenOrRecover(recovery) = %#v,%v", recovered, err)
	}
	initial, err = recovered.Initial()
	if err != nil || initial {
		t.Fatalf("Initial(recovery lease) = %t,%v", initial, err)
	}

	fixture.dropNextRevokeResponse()
	if err := clientB.Revoke(t.Context(), recovered); err != nil {
		t.Fatalf("Revoke(recovery) error = %v", err)
	}
	if err := clientB.Revoke(t.Context(), recovered); err != nil {
		t.Fatalf("Revoke(replay) error = %v", err)
	}
	openCalls, revokeCalls := fixture.logicalCalls()
	if openCalls != 1 || revokeCalls != 1 {
		t.Fatalf("logical calls = open:%d revoke:%d, want 1/1", openCalls, revokeCalls)
	}

	drifted := request
	drifted.RuntimeBindingDigest = transportDigest2
	if lease, err := clientB.OpenOrRecover(t.Context(), drifted); lease != nil ||
		!errors.Is(err, discoverycleanup.ErrSessionTransportDrift) {
		t.Fatalf("OpenOrRecover(binding drift) = %#v,%v", lease, err)
	}
	drifted = request
	drifted.Coordinates.RunID = transportRunID2
	drifted.Attempt.RunID = transportRunID2
	if lease, err := clientB.OpenOrRecover(t.Context(), drifted); lease != nil ||
		!errors.Is(err, discoverycleanup.ErrSessionTransportDrift) {
		t.Fatalf("OpenOrRecover(run drift) = %#v,%v", lease, err)
	}
	drifted = request
	drifted.Attempt.AttemptEpoch++
	if lease, err := clientB.OpenOrRecover(t.Context(), drifted); lease != nil ||
		!errors.Is(err, discoverycleanup.ErrSessionTransportDrift) {
		t.Fatalf("OpenOrRecover(epoch drift) = %#v,%v", lease, err)
	}

	receiptRequest := request
	receiptRequest.Attempt = discoveryqueue.CleanupAttempt{
		RunID: transportRunID, AttemptID: transportAttemptID2, AttemptEpoch: 1,
	}
	fixture.corruptNextOpenReceipt()
	corrupt, err := clientA.OpenOrRecover(t.Context(), receiptRequest)
	if err != nil || corrupt == nil {
		t.Fatalf("OpenOrRecover(corrupt receipt fixture) = %#v,%v", corrupt, err)
	}
	if err := clientA.Revoke(t.Context(), corrupt); !errors.Is(err, discoverycleanup.ErrSessionTransportDrift) {
		t.Fatalf("Revoke(corrupt receipt) error = %v, want drift", err)
	}

	opened.Destroy()
	recovered.Destroy()
	corrupt.Destroy()
}

func TestSessionTransportMTLSPeerIdentitySecretZeroWireAndSerialization(t *testing.T) {
	fixture := newSessionTransportAuthorityFixture(t)
	valid := fixture.clientOptions(t, "worker-a")

	wrongPeer := valid
	wrongPeer.ExpectedPeerIdentity = "spiffe://aiops.test/discovery-session-authority/foreign"
	client, err := discoverycleanup.NewSessionTransport(wrongPeer)
	if err != nil {
		t.Fatalf("NewSessionTransport(wrong expected peer) error = %v", err)
	}
	if lease, openErr := client.OpenOrRecover(t.Context(), transportOpenRequest()); lease != nil ||
		!errors.Is(openErr, discoverycleanup.ErrSessionTransportAuthentication) {
		t.Fatalf("OpenOrRecover(wrong peer) = %#v,%v", lease, openErr)
	}
	client.Destroy()
	if calls, _ := fixture.logicalCalls(); calls != 0 {
		t.Fatalf("wrong peer reached authority: logical opens = %d", calls)
	}

	tests := map[string]func(discoverycleanup.SessionTransportOptions) discoverycleanup.SessionTransportOptions{
		"no roots": func(value discoverycleanup.SessionTransportOptions) discoverycleanup.SessionTransportOptions {
			value.RootCAs = nil
			return value
		},
		"no client certificate": func(value discoverycleanup.SessionTransportOptions) discoverycleanup.SessionTransportOptions {
			value.ClientCertificate = tls.Certificate{}
			return value
		},
		"tls endpoint path": func(value discoverycleanup.SessionTransportOptions) discoverycleanup.SessionTransportOptions {
			value.BaseURL += "/mutable"
			return value
		},
		"wildcard server name": func(value discoverycleanup.SessionTransportOptions) discoverycleanup.SessionTransportOptions {
			value.ServerName = "*.test"
			return value
		},
		"non workload peer": func(value discoverycleanup.SessionTransportOptions) discoverycleanup.SessionTransportOptions {
			value.ExpectedPeerIdentity = "https://session-authority.test/identity"
			return value
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if candidate, newErr := discoverycleanup.NewSessionTransport(mutate(valid)); candidate != nil ||
				!errors.Is(newErr, discoverycleanup.ErrSessionTransportInvalid) {
				t.Fatalf("NewSessionTransport(invalid) = %#v,%v", candidate, newErr)
			}
		})
	}

	client, err = discoverycleanup.NewSessionTransport(valid)
	if err != nil {
		t.Fatalf("NewSessionTransport(valid) error = %v", err)
	}
	t.Cleanup(client.Destroy)
	lease, err := client.OpenOrRecover(t.Context(), transportOpenRequest())
	if err != nil {
		t.Fatalf("OpenOrRecover() error = %v", err)
	}
	copiedClient := *client
	if copiedLease, copiedErr := copiedClient.OpenOrRecover(
		t.Context(), transportOpenRequest(),
	); copiedLease != nil || !errors.Is(copiedErr, discoverycleanup.ErrSessionTransportInvalid) {
		t.Fatalf("copied transport OpenOrRecover = %#v,%v", copiedLease, copiedErr)
	}
	copiedLease := *lease
	if copiedErr := client.Revoke(t.Context(), &copiedLease); !errors.Is(
		copiedErr, discoverycleanup.ErrSessionTransportInvalid,
	) {
		t.Fatalf("copied lease Revoke error = %v", copiedErr)
	}
	if reconstructedErr := client.Revoke(
		t.Context(), &discoverycleanup.SessionLease{},
	); !errors.Is(reconstructedErr, discoverycleanup.ErrSessionTransportInvalid) {
		t.Fatalf("reconstructed lease Revoke error = %v", reconstructedErr)
	}
	wire := fixture.lastOpenWire()
	var document map[string]any
	if err := json.Unmarshal(wire, &document); err != nil {
		t.Fatalf("decode captured wire: %v", err)
	}
	if got, want := sortedKeys(document), []string{
		"attempt_epoch", "attempt_id", "run", "runtime_binding_digest", "version",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("wire keys = %v, want %v", got, want)
	}
	run, ok := document["run"].(map[string]any)
	if !ok {
		t.Fatalf("wire run = %#v", document["run"])
	}
	if got, want := sortedKeys(run), []string{"run_id", "tenant_id", "workspace_id"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("run keys = %v, want %v", got, want)
	}
	lowerWire := strings.ToLower(string(wire))
	for _, forbidden := range []string{
		"credential", "bearer", "token", "private_key", "tls_key", "endpoint",
		"bound_runtime", "session_handle", "header", "body",
	} {
		if strings.Contains(lowerWire, forbidden) {
			t.Fatalf("wire contains forbidden field %q: %s", forbidden, wire)
		}
	}
	if err := client.Revoke(t.Context(), lease); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	revokeWire := fixture.lastRevokeWire()
	document = nil
	if err := json.Unmarshal(revokeWire, &document); err != nil {
		t.Fatalf("decode captured revoke wire: %v", err)
	}
	if got, want := sortedKeys(document), []string{
		"attempt_epoch", "attempt_id", "receipt", "run", "runtime_binding_digest", "version",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("revoke wire keys = %v, want %v", got, want)
	}
	lowerWire = strings.ToLower(string(revokeWire))
	for _, forbidden := range []string{
		"credential", "bearer", "token", "private_key", "tls_key", "endpoint",
		"bound_runtime", "session_handle", "header", "body",
	} {
		if strings.Contains(lowerWire, forbidden) {
			t.Fatalf("revoke wire contains forbidden field %q: %s", forbidden, revokeWire)
		}
	}

	assertSensitiveSerializationRejected(t, valid)
	assertSensitiveSerializationRejected(t, client)
	assertSensitiveSerializationRejected(t, lease)
	for label, value := range map[string]any{
		"options": valid,
		"client":  client,
		"lease":   lease,
	} {
		rendered := fmt.Sprintf("%v %#v", value, value)
		if strings.Contains(rendered, transportAttemptID) ||
			strings.Contains(rendered, fixture.serverIdentity) ||
			strings.Contains(rendered, fixture.server.URL) {
			t.Fatalf("%s formatting leaked transport material: %q", label, rendered)
		}
	}
	lease.Destroy()
}

func TestSessionTransportRejectsEveryResponseTupleAndReceiptDrift(t *testing.T) {
	tests := []string{
		"run_id", "tenant_id", "workspace_id", "attempt_id", "attempt_epoch",
		"runtime_binding_digest", "receipt", "unknown_field",
	}
	for _, field := range tests {
		t.Run(field, func(t *testing.T) {
			fixture := newSessionTransportAuthorityFixture(t)
			client := fixture.newClient(t, "worker-a")
			t.Cleanup(client.Destroy)
			if field == "receipt" {
				lease, err := client.OpenOrRecover(t.Context(), transportOpenRequest())
				if err != nil {
					t.Fatalf("OpenOrRecover(receipt baseline) error = %v", err)
				}
				lease.Destroy()
			}
			fixture.mutateNextOpenResponse(field)
			lease, err := client.OpenOrRecover(t.Context(), transportOpenRequest())
			if lease != nil || (!errors.Is(err, discoverycleanup.ErrSessionTransportDrift) &&
				!errors.Is(err, discoverycleanup.ErrSessionTransportProtocol)) {
				t.Fatalf("OpenOrRecover(%s drift) = %#v,%v", field, lease, err)
			}
		})
	}
}

func transportOpenRequest() discoverycleanup.SessionOpenRequest {
	return discoverycleanup.SessionOpenRequest{
		Coordinates: discoveryqueue.RunCoordinates{
			Scope: assetcatalog.SourceScope{
				TenantID: transportTenantID, WorkspaceID: transportWorkspace,
			},
			RunID: transportRunID,
		},
		Attempt: discoveryqueue.CleanupAttempt{
			RunID: transportRunID, AttemptID: transportAttemptID, AttemptEpoch: 1,
		},
		RuntimeBindingDigest: transportDigest,
	}
}

func assertSensitiveSerializationRejected(t *testing.T, value any) {
	t.Helper()
	if _, err := json.Marshal(value); !errors.Is(err, discoverycleanup.ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal(%T) error = %v", value, err)
	}
	if marshaler, ok := value.(interface{ MarshalText() ([]byte, error) }); ok {
		if _, err := marshaler.MarshalText(); !errors.Is(err, discoverycleanup.ErrSensitiveSerialization) {
			t.Fatalf("MarshalText(%T) error = %v", value, err)
		}
	}
	if marshaler, ok := value.(interface{ MarshalBinary() ([]byte, error) }); ok {
		if _, err := marshaler.MarshalBinary(); !errors.Is(err, discoverycleanup.ErrSensitiveSerialization) {
			t.Fatalf("MarshalBinary(%T) error = %v", value, err)
		}
	}
}

type transportRunWire struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	RunID       string `json:"run_id"`
}

type transportOpenWire struct {
	Version              string           `json:"version"`
	Run                  transportRunWire `json:"run"`
	AttemptID            string           `json:"attempt_id"`
	AttemptEpoch         int64            `json:"attempt_epoch"`
	RuntimeBindingDigest string           `json:"runtime_binding_digest"`
}

type transportRevokeWire struct {
	transportOpenWire
	Receipt string `json:"receipt"`
}

type transportSessionRecord struct {
	request transportOpenWire
	receipt string
	creator string
	revoked bool
}

type sessionTransportAuthorityFixture struct {
	t              *testing.T
	server         *httptest.Server
	authority      *testpki.Authority
	serverIdentity string

	mu                 sync.Mutex
	records            map[string]*transportSessionRecord
	logicalOpenCalls   int
	logicalRevokeCalls int
	dropOpen           bool
	dropRevoke         bool
	corruptReceipt     bool
	responseMutation   string
	openWires          [][]byte
	revokeWires        [][]byte
}

func newSessionTransportAuthorityFixture(t *testing.T) *sessionTransportAuthorityFixture {
	t.Helper()
	now := time.Now().UTC()
	authority, err := testpki.NewAuthority("session-transport-test-ca", now)
	if err != nil {
		t.Fatalf("NewAuthority() error = %v", err)
	}
	serverIdentity := "spiffe://aiops.test/discovery-session-authority/shared"
	serverURI, _ := url.Parse(serverIdentity)
	serverCertificate, err := authority.IssueClient(testpki.ClientOptions{
		CommonName: "session-authority.test",
		URIs:       []*url.URL{serverURI},
		DNSNames:   []string{"session-authority.test"},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}, now)
	if err != nil {
		t.Fatalf("Issue server certificate: %v", err)
	}
	fixture := &sessionTransportAuthorityFixture{
		t: t, authority: authority, serverIdentity: serverIdentity,
		records: make(map[string]*transportSessionRecord),
	}
	fixture.server = httptest.NewUnstartedServer(http.HandlerFunc(fixture.serveHTTP))
	fixture.server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate.TLS},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    authority.CertPool(),
		NextProtos:   []string{"http/1.1"},
	}
	fixture.server.StartTLS()
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *sessionTransportAuthorityFixture) clientOptions(
	t *testing.T,
	worker string,
) discoverycleanup.SessionTransportOptions {
	t.Helper()
	identity, _ := url.Parse("spiffe://aiops.test/discovery-worker/" + worker)
	certificate, err := fixture.authority.IssueClient(testpki.ClientOptions{
		CommonName: worker, URIs: []*url.URL{identity},
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("IssueClient(%s) error = %v", worker, err)
	}
	return discoverycleanup.SessionTransportOptions{
		BaseURL: fixture.server.URL, ServerName: "session-authority.test",
		ExpectedPeerIdentity: fixture.serverIdentity,
		RootCAs:              fixture.authority.CertPool(),
		ClientCertificate:    certificate.TLS,
	}
}

func (fixture *sessionTransportAuthorityFixture) newClient(
	t *testing.T,
	worker string,
) *discoverycleanup.SessionTransport {
	t.Helper()
	client, err := discoverycleanup.NewSessionTransport(fixture.clientOptions(t, worker))
	if err != nil {
		t.Fatalf("NewSessionTransport(%s) error = %v", worker, err)
	}
	return client
}

func (fixture *sessionTransportAuthorityFixture) serveHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.ProtoMajor != 1 || request.TLS == nil || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) == 0 || len(request.TLS.PeerCertificates[0].URIs) != 1 {
		fixture.writeProblem(writer, http.StatusUnauthorized)
		return
	}
	peer := request.TLS.PeerCertificates[0].URIs[0].String()
	body, err := io.ReadAll(io.LimitReader(request.Body, 8193))
	if err != nil || len(body) == 0 || len(body) > 8192 {
		fixture.writeProblem(writer, http.StatusBadRequest)
		return
	}
	switch request.URL.Path {
	case sessionOpenPath:
		fixture.serveOpen(writer, body, peer)
	case sessionRevokePath:
		fixture.serveRevoke(writer, body)
	default:
		fixture.writeProblem(writer, http.StatusNotFound)
	}
}

func (fixture *sessionTransportAuthorityFixture) serveOpen(
	writer http.ResponseWriter,
	body []byte,
	peer string,
) {
	var wire transportOpenWire
	if decodeStrictTestJSON(body, &wire) != nil {
		fixture.writeProblem(writer, http.StatusBadRequest)
		return
	}
	fixture.mu.Lock()
	fixture.openWires = append(fixture.openWires, bytes.Clone(body))
	record := fixture.records[wire.AttemptID]
	if record != nil && !reflect.DeepEqual(record.request, wire) {
		fixture.mu.Unlock()
		fixture.writeProblem(writer, http.StatusConflict)
		return
	}
	if record == nil {
		digest := sha256.Sum256([]byte(fmt.Sprintf("%#v", wire)))
		record = &transportSessionRecord{
			request: wire, receipt: hex.EncodeToString(digest[:]), creator: peer,
		}
		fixture.records[wire.AttemptID] = record
		fixture.logicalOpenCalls++
	}
	disposition := "RECOVERED"
	if record.creator == peer {
		disposition = "OPENED"
	}
	receipt := record.receipt
	if fixture.corruptReceipt {
		fixture.corruptReceipt = false
		receipt = strings.Repeat("f", 64)
	}
	response := map[string]any{
		"version": "discovery-cleanup-session.v1",
		"run": map[string]any{
			"tenant_id": wire.Run.TenantID, "workspace_id": wire.Run.WorkspaceID,
			"run_id": wire.Run.RunID,
		},
		"attempt_id": wire.AttemptID, "attempt_epoch": wire.AttemptEpoch,
		"runtime_binding_digest": wire.RuntimeBindingDigest,
		"receipt":                receipt, "disposition": disposition,
	}
	fixture.mutateOpenResponse(response)
	drop := fixture.dropOpen
	fixture.dropOpen = false
	fixture.mu.Unlock()
	if drop {
		fixture.writePartialJSON(writer)
		panic(http.ErrAbortHandler)
	}
	fixture.writeJSON(writer, response)
}

func (fixture *sessionTransportAuthorityFixture) serveRevoke(
	writer http.ResponseWriter,
	body []byte,
) {
	var wire transportRevokeWire
	if decodeStrictTestJSON(body, &wire) != nil {
		fixture.writeProblem(writer, http.StatusBadRequest)
		return
	}
	fixture.mu.Lock()
	fixture.revokeWires = append(fixture.revokeWires, bytes.Clone(body))
	record := fixture.records[wire.AttemptID]
	if record == nil || !reflect.DeepEqual(record.request, wire.transportOpenWire) ||
		record.receipt != wire.Receipt {
		fixture.mu.Unlock()
		fixture.writeProblem(writer, http.StatusConflict)
		return
	}
	if !record.revoked {
		record.revoked = true
		fixture.logicalRevokeCalls++
	}
	drop := fixture.dropRevoke
	fixture.dropRevoke = false
	response := map[string]any{
		"version": "discovery-cleanup-session.v1",
		"run": map[string]any{
			"tenant_id": wire.Run.TenantID, "workspace_id": wire.Run.WorkspaceID,
			"run_id": wire.Run.RunID,
		},
		"attempt_id": wire.AttemptID, "attempt_epoch": wire.AttemptEpoch,
		"runtime_binding_digest": wire.RuntimeBindingDigest,
		"receipt":                wire.Receipt, "status": "REVOKED",
	}
	fixture.mu.Unlock()
	if drop {
		fixture.writePartialJSON(writer)
		panic(http.ErrAbortHandler)
	}
	fixture.writeJSON(writer, response)
}

func (fixture *sessionTransportAuthorityFixture) mutateOpenResponse(response map[string]any) {
	field := fixture.responseMutation
	fixture.responseMutation = ""
	run := response["run"].(map[string]any)
	switch field {
	case "run_id":
		run["run_id"] = transportRunID2
	case "tenant_id":
		run["tenant_id"] = transportWorkspace
	case "workspace_id":
		run["workspace_id"] = transportTenantID
	case "attempt_id":
		response["attempt_id"] = transportAttemptID2
	case "attempt_epoch":
		response["attempt_epoch"] = float64(99)
	case "runtime_binding_digest":
		response["runtime_binding_digest"] = transportDigest2
	case "receipt":
		response["receipt"] = strings.Repeat("e", 64)
	case "unknown_field":
		response["credential"] = "forbidden"
	}
}

func (fixture *sessionTransportAuthorityFixture) writeJSON(
	writer http.ResponseWriter,
	value any,
) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(value)
}

func (fixture *sessionTransportAuthorityFixture) writeProblem(
	writer http.ResponseWriter,
	status int,
) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, `{"code":"session_rejected"}`)
}

func (fixture *sessionTransportAuthorityFixture) writePartialJSON(
	writer http.ResponseWriter,
) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", "1024")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(writer, `{"version":"discovery-cleanup-session.v1","run":`)
	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (fixture *sessionTransportAuthorityFixture) dropNextOpenResponse() {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.dropOpen = true
}

func (fixture *sessionTransportAuthorityFixture) dropNextRevokeResponse() {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.dropRevoke = true
}

func (fixture *sessionTransportAuthorityFixture) corruptNextOpenReceipt() {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.corruptReceipt = true
}

func (fixture *sessionTransportAuthorityFixture) mutateNextOpenResponse(field string) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.responseMutation = field
}

func (fixture *sessionTransportAuthorityFixture) logicalCalls() (int, int) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.logicalOpenCalls, fixture.logicalRevokeCalls
}

func (fixture *sessionTransportAuthorityFixture) lastOpenWire() []byte {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.openWires) == 0 {
		return nil
	}
	return bytes.Clone(fixture.openWires[len(fixture.openWires)-1])
}

func (fixture *sessionTransportAuthorityFixture) lastRevokeWire() []byte {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.revokeWires) == 0 {
		return nil
	}
	return bytes.Clone(fixture.revokeWires[len(fixture.revokeWires)-1])
}

func decodeStrictTestJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slicesSort(keys)
	return keys
}

func slicesSort(values []string) {
	for index := 1; index < len(values); index++ {
		for position := index; position > 0 && values[position] < values[position-1]; position-- {
			values[position], values[position-1] = values[position-1], values[position]
		}
	}
}
