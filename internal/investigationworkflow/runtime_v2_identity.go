package investigationworkflow

import (
	"encoding/json"
	"reflect"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	commonpb "go.temporal.io/api/common/v1"
	"google.golang.org/protobuf/proto"
)

const RuntimeMemoIdentityKeyV2 = "aiops.investigation.read.identity.v2"

func canonicalWorkflowInputV2Payload(input WorkflowInputV2) (*commonpb.Payload, error) {
	if input.Validate() != nil {
		return nil, ErrInvalidRuntimeV2Input
	}
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumHistoryDTOBytes {
		return nil, ErrInvalidRuntimeV2Input
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil || len(canonical) == 0 || len(canonical) > maximumHistoryDTOBytes {
		return nil, ErrInvalidRuntimeV2Input
	}
	var decoded WorkflowInputV2
	if err := json.Unmarshal(canonical, &decoded); err != nil || !reflect.DeepEqual(decoded, input) {
		return nil, ErrInvalidRuntimeV2Input
	}
	payload := &commonpb.Payload{
		Metadata: map[string][]byte{"encoding": []byte("json/plain")},
		Data:     canonical,
	}
	if proto.Size(payload) > maximumHistoryDTOBytes {
		return nil, ErrInvalidRuntimeV2Input
	}
	return payload, nil
}

func ValidTemporalRunID(runID string) bool {
	return temporalRunUUID.MatchString(runID)
}
