package investigationworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/proto"
)

var (
	errRuntimeV2PayloadRejected = errors.New("investigation READ runtime payload rejected")
	runtimeV2ConverterSeal      = &runtimeV2ConverterMarker{value: 1}
)

type runtimeV2ConverterMarker struct{ value byte }

// runtimeV2DataConverter is the package-owned, closed serialization profile
// for the v2 READ protocol. It deliberately has no fallback converter.
type runtimeV2DataConverter struct {
	seal *runtimeV2ConverterMarker
	self *runtimeV2DataConverter
}

var (
	_ converter.DataConverter                         = (*runtimeV2DataConverter)(nil)
	_ converter.DataConverterWithSerializationContext = (*runtimeV2DataConverter)(nil)
	_ workflow.ContextAware                           = (*runtimeV2DataConverter)(nil)
)

func newRuntimeV2DataConverter() (*runtimeV2DataConverter, error) {
	created := &runtimeV2DataConverter{seal: runtimeV2ConverterSeal}
	created.self = created
	return created, nil
}

func (dataConverter *runtimeV2DataConverter) valid() bool {
	return dataConverter != nil && dataConverter.seal == runtimeV2ConverterSeal && dataConverter.self == dataConverter
}

func (dataConverter *runtimeV2DataConverter) ToPayload(value interface{}) (*commonpb.Payload, error) {
	if !dataConverter.valid() {
		return nil, errRuntimeV2PayloadRejected
	}
	if identity, ok := value.(runtimeV2MemoIdentity); ok {
		var input WorkflowInputV2
		if err := decodeRuntimeV2Payload(identity.payload, &input); err != nil {
			return nil, errRuntimeV2PayloadRejected
		}
		return proto.Clone(identity.payload).(*commonpb.Payload), nil
	}
	normalized, destination, ok := runtimeV2JSONValue(value)
	if !ok {
		return nil, errRuntimeV2PayloadRejected
	}
	encoded, err := json.Marshal(normalized)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumHistoryDTOBytes {
		return nil, errRuntimeV2PayloadRejected
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil || len(canonical) == 0 || len(canonical) > maximumHistoryDTOBytes {
		return nil, errRuntimeV2PayloadRejected
	}
	if err := json.Unmarshal(canonical, destination); err != nil ||
		!reflect.DeepEqual(reflect.ValueOf(destination).Elem().Interface(), normalized) {
		return nil, errRuntimeV2PayloadRejected
	}
	payload := &commonpb.Payload{
		Metadata: map[string][]byte{converter.MetadataEncoding: []byte(converter.MetadataEncodingJSON)},
		Data:     canonical,
	}
	if proto.Size(payload) > maximumHistoryDTOBytes {
		return nil, errRuntimeV2PayloadRejected
	}
	return payload, nil
}

func (dataConverter *runtimeV2DataConverter) FromPayload(payload *commonpb.Payload, valuePtr interface{}) error {
	if !dataConverter.valid() {
		return errRuntimeV2PayloadRejected
	}
	return decodeRuntimeV2Payload(payload, valuePtr)
}

func decodeRuntimeV2Payload(payload *commonpb.Payload, valuePtr interface{}) error {
	if payload == nil || proto.Size(payload) > maximumHistoryDTOBytes ||
		len(payload.Metadata) != 1 ||
		!bytes.Equal(payload.Metadata[converter.MetadataEncoding], []byte(converter.MetadataEncodingJSON)) ||
		len(payload.Data) == 0 || len(payload.Data) > maximumHistoryDTOBytes {
		return errRuntimeV2PayloadRejected
	}
	canonical, err := jsoncanonicalizer.Transform(payload.Data)
	if err != nil || !bytes.Equal(canonical, payload.Data) {
		return errRuntimeV2PayloadRejected
	}
	return decodeRuntimeV2JSON(payload.Data, valuePtr)
}

func (dataConverter *runtimeV2DataConverter) ToPayloads(values ...interface{}) (*commonpb.Payloads, error) {
	if !dataConverter.valid() {
		return nil, errRuntimeV2PayloadRejected
	}
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 {
		return nil, errRuntimeV2PayloadRejected
	}
	payload, err := dataConverter.ToPayload(values[0])
	if err != nil {
		return nil, errRuntimeV2PayloadRejected
	}
	payloads := &commonpb.Payloads{Payloads: []*commonpb.Payload{payload}}
	if proto.Size(payloads) > maximumHistoryDTOBytes {
		return nil, errRuntimeV2PayloadRejected
	}
	return payloads, nil
}

func (dataConverter *runtimeV2DataConverter) FromPayloads(
	payloads *commonpb.Payloads,
	valuePtrs ...interface{},
) error {
	if !dataConverter.valid() {
		return errRuntimeV2PayloadRejected
	}
	if payloads == nil && len(valuePtrs) == 0 {
		return nil
	}
	if payloads == nil || proto.Size(payloads) > maximumHistoryDTOBytes ||
		len(payloads.Payloads) != 1 || len(valuePtrs) != 1 {
		return errRuntimeV2PayloadRejected
	}
	return dataConverter.FromPayload(payloads.Payloads[0], valuePtrs[0])
}

func (dataConverter *runtimeV2DataConverter) ToString(payload *commonpb.Payload) string {
	if !dataConverter.valid() || payload == nil {
		return "<runtime-v2-payload-unavailable>"
	}
	return "<runtime-v2-payload>"
}

func (dataConverter *runtimeV2DataConverter) ToStrings(payloads *commonpb.Payloads) []string {
	if !dataConverter.valid() || payloads == nil || len(payloads.Payloads) != 1 {
		return nil
	}
	return []string{dataConverter.ToString(payloads.Payloads[0])}
}

func (dataConverter *runtimeV2DataConverter) WithContext(context.Context) converter.DataConverter {
	if !dataConverter.valid() {
		return &runtimeV2DataConverter{}
	}
	return dataConverter
}

func (dataConverter *runtimeV2DataConverter) WithWorkflowContext(workflow.Context) converter.DataConverter {
	if !dataConverter.valid() {
		return &runtimeV2DataConverter{}
	}
	return dataConverter
}

func (dataConverter *runtimeV2DataConverter) WithSerializationContext(
	converter.SerializationContext,
) converter.DataConverter {
	if !dataConverter.valid() {
		return &runtimeV2DataConverter{}
	}
	return dataConverter
}

type runtimeV2MemoIdentity struct {
	payload *commonpb.Payload
}

func (runtimeV2MemoIdentity) MarshalJSON() ([]byte, error) {
	return nil, errRuntimeV2PayloadRejected
}

func (*runtimeV2MemoIdentity) UnmarshalJSON([]byte) error {
	return errRuntimeV2PayloadRejected
}

func newRuntimeV2MemoIdentity(
	input WorkflowInputV2,
) (runtimeV2MemoIdentity, *commonpb.Payload, error) {
	dataConverter, err := newRuntimeV2DataConverter()
	if err != nil {
		return runtimeV2MemoIdentity{}, nil, errRuntimeV2PayloadRejected
	}
	payload, err := dataConverter.ToPayload(input)
	if err != nil {
		return runtimeV2MemoIdentity{}, nil, errRuntimeV2PayloadRejected
	}
	return runtimeV2MemoIdentity{payload: proto.Clone(payload).(*commonpb.Payload)}, payload, nil
}

func runtimeV2JSONValue(value interface{}) (interface{}, interface{}, bool) {
	switch value := value.(type) {
	case WorkflowInputV2:
		return value, &WorkflowInputV2{}, true
	case *WorkflowInputV2:
		if value != nil {
			return *value, &WorkflowInputV2{}, true
		}
	case WorkflowResultV2:
		return value, &WorkflowResultV2{}, true
	case *WorkflowResultV2:
		if value != nil {
			return *value, &WorkflowResultV2{}, true
		}
	case PreparationReceiptV2:
		return value, &PreparationReceiptV2{}, true
	case *PreparationReceiptV2:
		if value != nil {
			return *value, &PreparationReceiptV2{}, true
		}
	case ReadTaskActivityInputV1:
		return value, &ReadTaskActivityInputV1{}, true
	case *ReadTaskActivityInputV1:
		if value != nil {
			return *value, &ReadTaskActivityInputV1{}, true
		}
	case ReadTaskActivityOutputV1:
		return value, &ReadTaskActivityOutputV1{}, true
	case *ReadTaskActivityOutputV1:
		if value != nil {
			return *value, &ReadTaskActivityOutputV1{}, true
		}
	case RecoveryActivityInput:
		return value, &RecoveryActivityInput{}, true
	case *RecoveryActivityInput:
		if value != nil {
			return *value, &RecoveryActivityInput{}, true
		}
	case RecoveryActivityOutput:
		return value, &RecoveryActivityOutput{}, true
	case *RecoveryActivityOutput:
		if value != nil {
			return *value, &RecoveryActivityOutput{}, true
		}
	}
	return nil, nil, false
}

func decodeRuntimeV2JSON(data []byte, valuePtr interface{}) error {
	switch destination := valuePtr.(type) {
	case *WorkflowInputV2:
		if destination == nil {
			break
		}
		var decoded WorkflowInputV2
		if json.Unmarshal(data, &decoded) == nil {
			*destination = decoded
			return nil
		}
	case *WorkflowResultV2:
		if destination == nil {
			break
		}
		var decoded WorkflowResultV2
		if json.Unmarshal(data, &decoded) == nil {
			*destination = decoded
			return nil
		}
	case *PreparationReceiptV2:
		if destination == nil {
			break
		}
		var decoded PreparationReceiptV2
		if json.Unmarshal(data, &decoded) == nil {
			*destination = decoded
			return nil
		}
	case *ReadTaskActivityInputV1:
		if destination == nil {
			break
		}
		var decoded ReadTaskActivityInputV1
		if json.Unmarshal(data, &decoded) == nil {
			*destination = decoded
			return nil
		}
	case *ReadTaskActivityOutputV1:
		if destination == nil {
			break
		}
		var decoded ReadTaskActivityOutputV1
		if json.Unmarshal(data, &decoded) == nil {
			*destination = decoded
			return nil
		}
	case *RecoveryActivityInput:
		if destination == nil {
			break
		}
		var decoded RecoveryActivityInput
		if json.Unmarshal(data, &decoded) == nil {
			*destination = decoded
			return nil
		}
	case *RecoveryActivityOutput:
		if destination == nil {
			break
		}
		var decoded RecoveryActivityOutput
		if json.Unmarshal(data, &decoded) == nil {
			*destination = decoded
			return nil
		}
	}
	return errRuntimeV2PayloadRejected
}
