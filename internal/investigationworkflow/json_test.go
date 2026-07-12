package investigationworkflow_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
)

func TestHistoryDTOsRejectUnknownDuplicateAndOversizedJSON(t *testing.T) {
	input, err := json.Marshal(validWorkflowInput())
	if err != nil {
		t.Fatalf("json.Marshal(input) error = %v", err)
	}
	receipt, err := json.Marshal(validReceipt())
	if err != nil {
		t.Fatalf("json.Marshal(receipt) error = %v", err)
	}
	inputCases := map[string][]byte{
		"unknown":    bytes.Replace(input, []byte(`{"version":`), []byte(`{"unknown":"canary","version":`), 1),
		"duplicate":  bytes.Replace(input, []byte(`{"version":1`), []byte(`{"version":1,"version":1`), 1),
		"root array": []byte(`[]`),
		"trailing":   append(append([]byte(nil), input...), []byte(`{}`)...),
		"oversized":  append(append([]byte(`{"unknown":"`), bytes.Repeat([]byte{'x'}, 4097)...), []byte(`"}`)...),
	}
	for name, encoded := range inputCases {
		t.Run("input "+name, func(t *testing.T) {
			var decoded investigationworkflow.WorkflowInput
			if err := json.Unmarshal(encoded, &decoded); err == nil {
				t.Fatalf("json.Unmarshal(input) error = %v", err)
			}
		})
	}
	receiptCases := map[string][]byte{
		"unknown":    bytes.Replace(receipt, []byte(`{"version":`), []byte(`{"unknown":"canary","version":`), 1),
		"duplicate":  bytes.Replace(receipt, []byte(`{"version":1`), []byte(`{"version":1,"version":1`), 1),
		"root array": []byte(`[]`),
		"trailing":   append(append([]byte(nil), receipt...), []byte(`{}`)...),
		"oversized":  append(append([]byte(`{"unknown":"`), bytes.Repeat([]byte{'x'}, 4097)...), []byte(`"}`)...),
	}
	for name, encoded := range receiptCases {
		t.Run("receipt "+name, func(t *testing.T) {
			var decoded investigationworkflow.PreparationReceipt
			if err := json.Unmarshal(encoded, &decoded); err == nil {
				t.Fatalf("json.Unmarshal(receipt) error = %v", err)
			}
		})
	}
	var roundTripInput investigationworkflow.WorkflowInput
	if err := json.Unmarshal(input, &roundTripInput); err != nil {
		t.Fatalf("json.Unmarshal(valid input) error = %v", err)
	}
	var roundTripReceipt investigationworkflow.PreparationReceipt
	if err := json.Unmarshal(receipt, &roundTripReceipt); err != nil {
		t.Fatalf("json.Unmarshal(valid receipt) error = %v", err)
	}
}
