package investigationworkflow

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	commonpb "go.temporal.io/api/common/v1"
	historypb "go.temporal.io/api/history/v1"
	workflowservicepb "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/interceptor"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/seaworld008/aiops-system/internal/outbox"
)

func TestMemoIdentityIsCanonicalExactBoundedAndFallbackProof(t *testing.T) {
	input := internalValidWorkflowInput()
	identity, expected, err := newMemoIdentity(input)
	if err != nil {
		t.Fatalf("newMemoIdentity() error = %v", err)
	}
	router, err := newMemoRoutingDataConverter(converter.GetDefaultDataConverter())
	if err != nil {
		t.Fatalf("newMemoRoutingDataConverter() error = %v", err)
	}
	first, err := router.ToPayload(identity)
	if err != nil {
		t.Fatalf("ToPayload(identity) error = %v", err)
	}
	second, err := router.ToPayload(identity)
	if err != nil {
		t.Fatalf("ToPayload(identity again) error = %v", err)
	}
	if !proto.Equal(first, expected) || !proto.Equal(second, expected) || first == expected || second == expected ||
		first == second || proto.Size(first) > maximumMemoPayloadBytes {
		t.Fatalf("memo payload is not an exact bounded deep clone: first=%#v second=%#v expected=%#v", first, second, expected)
	}
	if len(first.Metadata) != 1 || string(first.Metadata[converter.MetadataEncoding]) != converter.MetadataEncodingJSON {
		t.Fatalf("memo metadata = %#v", first.Metadata)
	}
	decoded, err := decodeWorkflowInputPayload(first)
	if err != nil || !reflect.DeepEqual(decoded, input) {
		t.Fatalf("decodeWorkflowInputPayload() = %#v, %v", decoded, err)
	}
	canonicalKeys := []string{`"aggregate_version":`, `"manifest_digest":`, `"outbox_event_id":`, `"registry_digest":`, `"signal_id":`, `"tenant_id":`, `"version":`, `"workspace_id":`}
	last := -1
	for _, key := range canonicalKeys {
		index := bytes.Index(first.Data, []byte(key))
		if index <= last {
			t.Fatalf("memo is not JCS key ordered: %s", first.Data)
		}
		last = index
	}
	first.Data[0] = '['
	if proto.Equal(first, expected) {
		t.Fatal("mutating returned payload also mutated sealed identity")
	}

	if _, err := router.ToPayload(memoIdentityV1{}); !errors.Is(err, errMemoIdentityRejected) {
		t.Fatalf("ToPayload(zero identity) error = %v", err)
	}
	if _, err := json.Marshal(memoIdentityV1{}); !errors.Is(err, errMemoIdentityRejected) {
		t.Fatalf("json.Marshal(zero identity) error = %v", err)
	}
	var fallback memoIdentityV1
	if err := json.Unmarshal([]byte(`{}`), &fallback); !errors.Is(err, errMemoIdentityRejected) {
		t.Fatalf("json.Unmarshal(identity) error = %v", err)
	}
	if _, err := router.ToPayloads(identity); !errors.Is(err, errMemoIdentityRejected) {
		t.Fatalf("ToPayloads(identity) error = %v", err)
	}
}

func TestMemoIdentityRejectsNonCanonicalUnknownDuplicateMetadataAndOversize(t *testing.T) {
	_, valid, err := newMemoIdentity(internalValidWorkflowInput())
	if err != nil {
		t.Fatalf("newMemoIdentity() error = %v", err)
	}
	mutations := map[string]func(*commonpb.Payload){
		"nil data": func(payload *commonpb.Payload) { payload.Data = nil },
		"metadata extra": func(payload *commonpb.Payload) {
			payload.Metadata["extra"] = []byte("value")
		},
		"metadata encoding": func(payload *commonpb.Payload) {
			payload.Metadata[converter.MetadataEncoding] = []byte("binary/plain")
		},
		"noncanonical": func(payload *commonpb.Payload) {
			var value map[string]interface{}
			if err := json.Unmarshal(payload.Data, &value); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			payload.Data = []byte(`{"version":1,"workspace_id":"44444444-4444-4444-8444-444444444444","tenant_id":"22222222-2222-4222-8222-222222222222","signal_id":"33333333-3333-4333-8333-333333333333","registry_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","outbox_event_id":"11111111-1111-4111-8111-111111111111","manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","aggregate_version":1}`)
		},
		"unknown": func(payload *commonpb.Payload) {
			payload.Data = bytes.Replace(payload.Data, []byte(`"workspace_id":`), []byte(`"unknown":0,"workspace_id":`), 1)
		},
		"duplicate": func(payload *commonpb.Payload) {
			payload.Data = bytes.Replace(payload.Data, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
		},
		"oversize": func(payload *commonpb.Payload) { payload.Data = bytes.Repeat([]byte{'x'}, maximumMemoPayloadBytes) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			payload := proto.Clone(valid).(*commonpb.Payload)
			mutate(payload)
			if _, err := decodeWorkflowInputPayload(payload); !errors.Is(err, errMemoIdentityRejected) {
				t.Fatalf("decodeWorkflowInputPayload(%s) error = %v", name, err)
			}
		})
	}
}

func TestMemoRouterBypassesRandomCodecAcrossRequestContextsAndDelegatesOtherPayloads(t *testing.T) {
	var nonce atomic.Uint64
	trace := make([]string, 0, 12)
	base := converter.NewCodecDataConverter(converter.GetDefaultDataConverter(), &nonceCodec{nonce: &nonce})
	delegate := &contextProbeDataConverter{DataConverter: base, trace: &trace}
	router, err := newMemoRoutingDataConverter(delegate)
	if err != nil {
		t.Fatalf("newMemoRoutingDataConverter() error = %v", err)
	}
	identity, expected, err := newMemoIdentity(internalValidWorkflowInput())
	if err != nil {
		t.Fatalf("newMemoIdentity() error = %v", err)
	}

	firstContext := context.WithValue(context.Background(), probeContextKey{}, "first-request")
	firstRouter := router.WithContext(firstContext)
	firstRouter = converter.WithDataConverterSerializationContext(firstRouter, converter.WorkflowSerializationContext{
		Namespace: "default", WorkflowID: internalWorkflowOutboxID,
	})
	firstMemo, err := firstRouter.ToPayload(identity)
	if err != nil {
		t.Fatalf("first ToPayload(identity) error = %v", err)
	}
	firstBusiness, err := firstRouter.ToPayload("delegated-business-payload")
	if err != nil {
		t.Fatalf("first ToPayload(business) error = %v", err)
	}

	secondContext := context.WithValue(context.Background(), probeContextKey{}, "ACK-lost-redelivery")
	secondRouter := router.WithContext(secondContext)
	secondRouter = converter.WithDataConverterSerializationContext(secondRouter, converter.WorkflowSerializationContext{
		Namespace: "default", WorkflowID: internalWorkflowOutboxID,
	})
	secondMemo, err := secondRouter.ToPayload(identity)
	if err != nil {
		t.Fatalf("second ToPayload(identity) error = %v", err)
	}
	secondBusiness, err := secondRouter.ToPayload("delegated-business-payload")
	if err != nil {
		t.Fatalf("second ToPayload(business) error = %v", err)
	}

	if !proto.Equal(firstMemo, expected) || !proto.Equal(secondMemo, expected) || !proto.Equal(firstMemo, secondMemo) {
		t.Fatal("safe identity memo changed across request context or random codec nonce")
	}
	if proto.Equal(firstBusiness, secondBusiness) || string(firstBusiness.Metadata[converter.MetadataEncoding]) != "binary/test-nonce" {
		t.Fatalf("business payload did not traverse random codec: first=%#v second=%#v", firstBusiness, secondBusiness)
	}
	var decoded string
	if err := secondRouter.FromPayload(secondBusiness, &decoded); err != nil || decoded != "delegated-business-payload" {
		t.Fatalf("FromPayload(business) = %#v, %v", decoded, err)
	}
	wantTrace := []string{
		"legacy:first-request", "serialization:default/" + internalWorkflowOutboxID, "payload",
		"legacy:ACK-lost-redelivery", "serialization:default/" + internalWorkflowOutboxID, "payload", "from-payload",
	}
	if !reflect.DeepEqual(trace, wantTrace) {
		t.Fatalf("delegate trace = %#v, want %#v", trace, wantTrace)
	}
}

func TestMemoRouterPropagatesWorkflowContextAndFailsClosedOnTypedNilAdaptation(t *testing.T) {
	var typedNil *contextProbeDataConverter
	delegate := &contextProbeDataConverter{
		DataConverter:  converter.GetDefaultDataConverter(),
		workflowResult: typedNil,
		contextResult:  typedNil,
	}
	router, err := newMemoRoutingDataConverter(delegate)
	if err != nil {
		t.Fatalf("newMemoRoutingDataConverter() error = %v", err)
	}
	adapted := router.WithContext(context.Background())
	if _, err := adapted.ToPayload("business"); !errors.Is(err, errTemporalClientRejected) {
		t.Fatalf("typed-nil context adaptation ToPayload() error = %v", err)
	}
	identity, payload, err := newMemoIdentity(internalValidWorkflowInput())
	if err != nil {
		t.Fatalf("newMemoIdentity() error = %v", err)
	}
	if _, err := adapted.ToPayload(identity); !errors.Is(err, errTemporalClientRejected) {
		t.Fatalf("typed-nil ToPayload(identity) error = %v", err)
	}
	if _, err := adapted.ToPayloads(internalValidWorkflowInput()); !errors.Is(err, errTemporalClientRejected) {
		t.Fatalf("typed-nil ToPayloads(WorkflowInput) error = %v", err)
	}
	var input WorkflowInput
	if err := adapted.FromPayload(payload, &input); !errors.Is(err, errTemporalClientRejected) {
		t.Fatalf("typed-nil FromPayload(WorkflowInput) error = %v", err)
	}
	if err := adapted.FromPayloads(&commonpb.Payloads{Payloads: []*commonpb.Payload{payload}}, &input); !errors.Is(err, errTemporalClientRejected) {
		t.Fatalf("typed-nil FromPayloads(WorkflowInput) error = %v", err)
	}
	if _, err := router.WithWorkflowContext(nil).ToPayload("business"); !errors.Is(err, errTemporalClientRejected) {
		t.Fatalf("typed-nil workflow adaptation ToPayload() error = %v", err)
	}
	if _, err := (&memoRoutingDataConverter{}).ToPayload("business"); !errors.Is(err, errTemporalClientRejected) {
		t.Fatalf("nil delegate ToPayload() error = %v", err)
	}
}

func TestWorkflowInputRoutingRejectsOpaqueZipBombWithoutDelegateDecode(t *testing.T) {
	trace := make([]string, 0, 1)
	delegate := &contextProbeDataConverter{DataConverter: converter.GetDefaultDataConverter(), trace: &trace}
	router, err := newMemoRoutingDataConverter(delegate)
	if err != nil {
		t.Fatalf("newMemoRoutingDataConverter() error = %v", err)
	}
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write(bytes.Repeat([]byte{'x'}, 1<<20)); err != nil {
		t.Fatalf("zlib.Write() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zlib.Close() error = %v", err)
	}
	opaque := &commonpb.Payload{
		Metadata: map[string][]byte{converter.MetadataEncoding: []byte("binary/zlib")}, Data: compressed.Bytes(),
	}
	var input WorkflowInput
	if err := router.FromPayload(opaque, &input); !errors.Is(err, errMemoIdentityRejected) {
		t.Fatalf("FromPayload(zip bomb WorkflowInput) error = %v", err)
	}
	if err := router.FromPayloads(&commonpb.Payloads{Payloads: []*commonpb.Payload{opaque}}, &input); !errors.Is(err, errMemoIdentityRejected) {
		t.Fatalf("FromPayloads(zip bomb WorkflowInput) error = %v", err)
	}
	if len(trace) != 0 {
		t.Fatalf("opaque WorkflowInput reached delegate decoder: %#v", trace)
	}
	valid, err := canonicalWorkflowInputPayload(internalValidWorkflowInput())
	if err != nil {
		t.Fatalf("canonicalWorkflowInputPayload() error = %v", err)
	}
	if err := router.FromPayload(valid, &input); err != nil || !reflect.DeepEqual(input, internalValidWorkflowInput()) {
		t.Fatalf("FromPayload(canonical WorkflowInput) = %#v, %v", input, err)
	}
	if len(trace) != 0 {
		t.Fatalf("canonical WorkflowInput reached delegate decoder: %#v", trace)
	}
}

func TestTemporalClientOptionsFailClosedBeforeDial(t *testing.T) {
	var typedNil *contextProbeDataConverter
	tests := map[string]func(*client.Options){
		"typed nil data converter": func(options *client.Options) { options.DataConverter = typedNil },
		"custom data converter": func(options *client.Options) {
			options.DataConverter = converter.NewCodecDataConverter(
				converter.GetDefaultDataConverter(),
				converter.NewZlibCodec(converter.ZlibCodecOptions{AlwaysEncode: true}),
			)
		},
		"caller identity": func(options *client.Options) { options.Identity = "secret-identity-canary" },
		"plugin":          func(options *client.Options) { options.Plugins = []client.Plugin{nil} },
		"external storage drivers": func(options *client.Options) {
			options.ExternalStorage.Drivers = []converter.StorageDriver{nil}
		},
		"external storage selector": func(options *client.Options) {
			options.ExternalStorage.DriverSelector = &testStorageSelector{}
		},
		"external storage threshold": func(options *client.Options) { options.ExternalStorage.PayloadSizeThreshold = 1 },
		"client interceptor":         func(options *client.Options) { options.Interceptors = []interceptor.ClientInterceptor{nil} },
		"traffic controller":         func(options *client.Options) { options.TrafficController = &rejectingTrafficController{} },
		"grpc dial option": func(options *client.Options) {
			options.ConnectionOptions.DialOptions = []grpc.DialOption{grpc.WithDefaultCallOptions()}
		},
		"context propagator": func(options *client.Options) { options.ContextPropagators = []workflow.ContextPropagator{nil} },
		"failure converter": func(options *client.Options) {
			options.FailureConverter = temporal.NewDefaultFailureConverter(temporal.DefaultFailureConverterOptions{})
		},
		"invalid namespace": func(options *client.Options) { options.Namespace = "space rejected" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := client.Options{HostPort: "127.0.0.1:1"}
			mutate(&options)
			if _, err := DialTemporalClient(context.Background(), options); !errors.Is(err, errTemporalClientRejected) {
				t.Fatalf("DialTemporalClient(%s) error = %v", name, err)
			}
		})
	}

	router, err := newMemoRoutingDataConverter(converter.GetDefaultDataConverter())
	if err != nil {
		t.Fatalf("newMemoRoutingDataConverter() error = %v", err)
	}
	if err := validateTemporalClientOptions(client.Options{DataConverter: router}); !errors.Is(err, errTemporalClientRejected) {
		t.Fatalf("validateTemporalClientOptions(double routing) error = %v", err)
	}
	if _, err := DialTemporalClient(nil, client.Options{}); !errors.Is(err, errTemporalClientRejected) {
		t.Fatalf("DialTemporalClient(nil context) error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DialTemporalClient(canceled, client.Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialTemporalClient(canceled context) error = %v", err)
	}
}

func TestTemporalClientSealRejectsZeroAndForgedValues(t *testing.T) {
	if (&TemporalClient{}).validForStarter() || (&TemporalClient{}).validForWorker() {
		t.Fatal("zero TemporalClient passed its seal")
	}
	forged := &TemporalClient{seal: &temporalClientMarker{value: 1}}
	if forged.validForStarter() || forged.validForWorker() {
		t.Fatal("forged TemporalClient passed its seal")
	}
}

func TestTemporalClientCopyAndCloseAreFailClosed(t *testing.T) {
	tests := map[string]interface{}{
		"normal close": nil,
		"close panic":  "sensitive-sdk-close-canary",
	}
	for name, closePanic := range tests {
		t.Run(name, func(t *testing.T) {
			router, err := newMemoRoutingDataConverter(converter.GetDefaultDataConverter())
			if err != nil {
				t.Fatalf("newMemoRoutingDataConverter() error = %v", err)
			}
			sdk := &recordingTemporalSDKClient{closePanic: closePanic}
			temporalClient, err := newTemporalClient(
				&canaryStarterTransport{}, sdk, router, defaultTemporalNamespace,
			)
			if err != nil {
				t.Fatalf("newTemporalClient() error = %v", err)
			}
			input := internalValidWorkflowInput()
			starter, err := NewStarter(temporalClient, input.ManifestDigest, input.RegistryDigest)
			if err != nil {
				t.Fatalf("NewStarter() error = %v", err)
			}

			copyValue := reflect.New(reflect.TypeOf(temporalClient).Elem())
			copyValue.Elem().Set(reflect.ValueOf(temporalClient).Elem())
			copied := copyValue.Interface().(*TemporalClient)
			if copied.validForStarter() || copied.validForWorker() {
				t.Fatal("copied TemporalClient passed its self seal")
			}
			if err := copied.Close(); !errors.Is(err, errTemporalClientRejected) {
				t.Fatalf("copied.Close() error = %v", err)
			}
			if got := sdk.closes.Load(); got != 0 {
				t.Fatalf("copied.Close() called SDK Close %d times", got)
			}

			firstCloseErr := temporalClient.Close()
			// Restore the pre-Close shallow snapshot into the original address.
			// The unique lifecycle pointer must retain its terminal state.
			reflect.ValueOf(temporalClient).Elem().Set(copyValue.Elem())
			secondCloseErr := temporalClient.Close()
			if closePanic == nil {
				if firstCloseErr != nil || secondCloseErr != nil {
					t.Fatalf("Close() errors = %v / %v", firstCloseErr, secondCloseErr)
				}
			} else if !errors.Is(firstCloseErr, errTemporalClientRejected) ||
				!errors.Is(secondCloseErr, errTemporalClientRejected) ||
				strings.Contains(firstCloseErr.Error(), "canary") || strings.Contains(secondCloseErr.Error(), "canary") {
				t.Fatalf("Close(panic) errors = %v / %v", firstCloseErr, secondCloseErr)
			}
			if got := sdk.closes.Load(); got != 1 {
				t.Fatalf("SDK Close calls = %d, want 1", got)
			}
			if temporalClient.validForStarter() || temporalClient.validForWorker() {
				t.Fatal("closed TemporalClient remains usable")
			}
			if _, err := NewStarter(temporalClient, input.ManifestDigest, input.RegistryDigest); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("NewStarter(closed client) error = %v", err)
			}
			outcome, err := starter.Start(context.Background(), outbox.SignalWorkflowStart{
				Version: SchemaVersion, WorkflowID: input.OutboxEventID, OutboxEventID: input.OutboxEventID,
				TenantID: input.TenantID, WorkspaceID: input.WorkspaceID, SignalID: input.SignalID, AggregateVersion: 1,
			})
			if err == nil || outcome != "" {
				t.Fatalf("existing Starter.Start(after Close) = %s, %v", outcome, err)
			}
		})
	}
}

func TestTemporalClientFormattingAndJSONNeverExposeTransport(t *testing.T) {
	const canary = "temporal-client-sensitive-canary"
	router, err := newMemoRoutingDataConverter(converter.GetDefaultDataConverter())
	if err != nil {
		t.Fatalf("newMemoRoutingDataConverter() error = %v", err)
	}
	transport := &canaryStarterTransport{canary: canary}
	temporalClient, err := newTemporalClient(transport, nil, router, defaultTemporalNamespace)
	if err != nil {
		t.Fatalf("newTemporalClient() error = %v", err)
	}
	for _, formatted := range []string{
		fmt.Sprint(temporalClient), fmt.Sprintf("%v", temporalClient), fmt.Sprintf("%+v", temporalClient), fmt.Sprintf("%#v", temporalClient),
	} {
		if formatted != "<aiops-temporal-client>" || strings.Contains(formatted, canary) {
			t.Fatalf("formatted TemporalClient = %q", formatted)
		}
	}
	if _, err := json.Marshal(temporalClient); !errors.Is(err, errTemporalClientRejected) {
		t.Fatalf("json.Marshal(TemporalClient) error = %v", err)
	}
	if err := json.Unmarshal([]byte(`{}`), temporalClient); !errors.Is(err, errTemporalClientRejected) {
		t.Fatalf("json.Unmarshal(TemporalClient) error = %v", err)
	}
}

type probeContextKey struct{}

type contextProbeDataConverter struct {
	converter.DataConverter
	trace          *[]string
	contextResult  converter.DataConverter
	workflowResult converter.DataConverter
}

func (dataConverter *contextProbeDataConverter) WithContext(ctx context.Context) converter.DataConverter {
	if dataConverter.trace != nil {
		*dataConverter.trace = append(*dataConverter.trace, "legacy:"+ctx.Value(probeContextKey{}).(string))
	}
	if dataConverter.contextResult != nil || nilInterface(dataConverter.contextResult) && reflect.TypeOf(dataConverter.contextResult) != nil {
		return dataConverter.contextResult
	}
	return dataConverter
}

func (dataConverter *contextProbeDataConverter) WithWorkflowContext(workflow.Context) converter.DataConverter {
	if dataConverter.workflowResult != nil || nilInterface(dataConverter.workflowResult) && reflect.TypeOf(dataConverter.workflowResult) != nil {
		return dataConverter.workflowResult
	}
	return dataConverter
}

func (dataConverter *contextProbeDataConverter) WithSerializationContext(ctx converter.SerializationContext) converter.DataConverter {
	if dataConverter.trace != nil {
		workflowContext, ok := ctx.(converter.WorkflowSerializationContext)
		if !ok {
			*dataConverter.trace = append(*dataConverter.trace, "serialization:unexpected")
		} else {
			*dataConverter.trace = append(*dataConverter.trace, "serialization:"+workflowContext.Namespace+"/"+workflowContext.WorkflowID)
		}
	}
	return dataConverter
}

func (dataConverter *contextProbeDataConverter) ToPayload(value interface{}) (*commonpb.Payload, error) {
	if dataConverter.trace != nil {
		*dataConverter.trace = append(*dataConverter.trace, "payload")
	}
	return dataConverter.DataConverter.ToPayload(value)
}

func (dataConverter *contextProbeDataConverter) FromPayload(payload *commonpb.Payload, valuePtr interface{}) error {
	if dataConverter.trace != nil {
		*dataConverter.trace = append(*dataConverter.trace, "from-payload")
	}
	return dataConverter.DataConverter.FromPayload(payload, valuePtr)
}

type nonceCodec struct{ nonce *atomic.Uint64 }

func (codec *nonceCodec) Encode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	encoded := make([]*commonpb.Payload, len(payloads))
	for index, payload := range payloads {
		wire, err := proto.Marshal(payload)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, 8)
		binary.BigEndian.PutUint64(nonce, codec.nonce.Add(1))
		encoded[index] = &commonpb.Payload{
			Metadata: map[string][]byte{converter.MetadataEncoding: []byte("binary/test-nonce")},
			Data:     append(nonce, wire...),
		}
	}
	return encoded, nil
}

func (*nonceCodec) Decode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	decoded := make([]*commonpb.Payload, len(payloads))
	for index, payload := range payloads {
		if string(payload.Metadata[converter.MetadataEncoding]) != "binary/test-nonce" {
			decoded[index] = payload
			continue
		}
		if len(payload.Data) < 8 {
			return nil, errors.New("test nonce payload rejected")
		}
		decoded[index] = &commonpb.Payload{}
		if err := proto.Unmarshal(payload.Data[8:], decoded[index]); err != nil {
			return nil, err
		}
	}
	return decoded, nil
}

type rejectingTrafficController struct{}

func (*rejectingTrafficController) CheckCallAllowed(context.Context, string, interface{}, interface{}) error {
	return errors.New("rejected")
}

type testStorageSelector struct{}

func (*testStorageSelector) SelectDriver(converter.StorageDriverStoreContext, *commonpb.Payload) (converter.StorageDriver, error) {
	return nil, nil
}

type canaryStarterTransport struct{ canary string }

type recordingTemporalSDKClient struct {
	client.Client
	closePanic interface{}
	closes     atomic.Int64
}

func (sdk *recordingTemporalSDKClient) Close() {
	sdk.closes.Add(1)
	if sdk.closePanic != nil {
		panic(sdk.closePanic)
	}
}

func (*canaryStarterTransport) ExecuteWorkflow(context.Context, client.StartWorkflowOptions, interface{}, ...interface{}) (client.WorkflowRun, error) {
	return nil, errors.New("unused")
}

func (*canaryStarterTransport) DescribeWorkflowExecution(context.Context, string, string) (*workflowservicepb.DescribeWorkflowExecutionResponse, error) {
	return nil, errors.New("unused")
}

func (*canaryStarterTransport) FirstWorkflowHistoryEvent(context.Context, string, string) (*historypb.HistoryEvent, error) {
	return nil, errors.New("unused")
}

func internalValidWorkflowInput() WorkflowInput {
	return WorkflowInput{
		Version: SchemaVersion, OutboxEventID: internalWorkflowOutboxID,
		TenantID:         "22222222-2222-4222-8222-222222222222",
		WorkspaceID:      "44444444-4444-4444-8444-444444444444",
		SignalID:         "33333333-3333-4333-8333-333333333333",
		AggregateVersion: 1,
		ManifestDigest:   strings.Repeat("a", 64), RegistryDigest: strings.Repeat("b", 64),
	}
}

const internalWorkflowOutboxID = "11111111-1111-4111-8111-111111111111"
