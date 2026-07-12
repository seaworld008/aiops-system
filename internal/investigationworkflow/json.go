package investigationworkflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const maximumHistoryDTOBytes = 4096

func (input *WorkflowInput) UnmarshalJSON(data []byte) error {
	if input == nil {
		return ErrInvalidInput
	}
	var decoded WorkflowInput
	err := decodeExactObject(data, ErrInvalidInput, map[string]func(*json.Decoder) error{
		"version":           func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Version) },
		"outbox_event_id":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.OutboxEventID) },
		"tenant_id":         func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TenantID) },
		"workspace_id":      func(decoder *json.Decoder) error { return decoder.Decode(&decoded.WorkspaceID) },
		"signal_id":         func(decoder *json.Decoder) error { return decoder.Decode(&decoded.SignalID) },
		"aggregate_version": func(decoder *json.Decoder) error { return decoder.Decode(&decoded.AggregateVersion) },
		"manifest_digest":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ManifestDigest) },
		"registry_digest":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.RegistryDigest) },
	})
	if err != nil {
		return ErrInvalidInput
	}
	*input = decoded
	return nil
}

func (receipt *PreparationReceipt) UnmarshalJSON(data []byte) error {
	if receipt == nil {
		return ErrInvalidReceipt
	}
	var decoded PreparationReceipt
	err := decodeExactObject(data, ErrInvalidReceipt, map[string]func(*json.Decoder) error{
		"version":          func(decoder *json.Decoder) error { return decoder.Decode(&decoded.Version) },
		"state":            func(decoder *json.Decoder) error { return decoder.Decode(&decoded.State) },
		"outbox_event_id":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.OutboxEventID) },
		"tenant_id":        func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TenantID) },
		"workspace_id":     func(decoder *json.Decoder) error { return decoder.Decode(&decoded.WorkspaceID) },
		"signal_id":        func(decoder *json.Decoder) error { return decoder.Decode(&decoded.SignalID) },
		"incident_id":      func(decoder *json.Decoder) error { return decoder.Decode(&decoded.IncidentID) },
		"investigation_id": func(decoder *json.Decoder) error { return decoder.Decode(&decoded.InvestigationID) },
		"task_ids":         func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TaskIDs) },
		"task_count":       func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TaskCount) },
		"manifest_digest":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ManifestDigest) },
		"registry_digest":  func(decoder *json.Decoder) error { return decoder.Decode(&decoded.RegistryDigest) },
		"profile_digest":   func(decoder *json.Decoder) error { return decoder.Decode(&decoded.ProfileDigest) },
		"tasks_hash":       func(decoder *json.Decoder) error { return decoder.Decode(&decoded.TasksHash) },
	})
	if err != nil {
		return ErrInvalidReceipt
	}
	*receipt = decoded
	return nil
}

func decodeExactObject(data []byte, sentinel error, fields map[string]func(*json.Decoder) error) error {
	if len(data) == 0 || len(data) > maximumHistoryDTOBytes || !json.Valid(data) {
		return sentinel
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return sentinel
	}
	seen := make(map[string]struct{}, len(fields))
	for decoder.More() {
		nameToken, err := decoder.Token()
		name, ok := nameToken.(string)
		decode, known := fields[name]
		if err != nil || !ok || !known {
			return sentinel
		}
		if _, duplicate := seen[name]; duplicate {
			return sentinel
		}
		seen[name] = struct{}{}
		if err := decode(decoder); err != nil {
			return sentinel
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return sentinel
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return sentinel
	}
	return nil
}
