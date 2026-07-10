package signal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/ids"
)

var (
	ErrInvalidPayload      = errors.New("invalid signal payload")
	ErrUnsupportedProvider = errors.New("unsupported signal provider")
)

type Repository interface {
	CreateSignal(context.Context, domain.Signal) (bool, error)
}

type Service struct {
	repository Repository
	now        func() time.Time
}

type IngestResult struct {
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
}

func NewService(repository Repository, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{repository: repository, now: now}
}

func (service *Service) Ingest(
	ctx context.Context,
	workspaceID string,
	integrationID string,
	provider string,
	payload []byte,
) (IngestResult, error) {
	if workspaceID == "" || integrationID == "" {
		return IngestResult{}, fmt.Errorf("%w: workspace and integration are required", ErrInvalidPayload)
	}

	signals, err := service.normalize(workspaceID, integrationID, provider, payload)
	if err != nil {
		return IngestResult{}, err
	}

	var result IngestResult
	for _, item := range signals {
		if err := item.Validate(); err != nil {
			return IngestResult{}, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
		}
		created, err := service.repository.CreateSignal(ctx, item)
		if err != nil {
			return IngestResult{}, err
		}
		if created {
			result.Accepted++
		} else {
			result.Duplicates++
		}
	}
	return result, nil
}

func (service *Service) normalize(workspaceID, integrationID, provider string, payload []byte) ([]domain.Signal, error) {
	switch provider {
	case "alertmanager":
		return service.normalizeAlertmanager(workspaceID, integrationID, payload)
	case "nightingale":
		return service.normalizeNightingale(workspaceID, integrationID, payload)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProvider, provider)
	}
}

type alertmanagerPayload struct {
	Status   string `json:"status"`
	GroupKey string `json:"groupKey"`
	Alerts   []struct {
		Fingerprint string            `json:"fingerprint"`
		StartsAt    string            `json:"startsAt"`
		Status      string            `json:"status"`
		Labels      map[string]string `json:"labels"`
	} `json:"alerts"`
}

func (service *Service) normalizeAlertmanager(workspaceID, integrationID string, payload []byte) ([]domain.Signal, error) {
	var incoming alertmanagerPayload
	if err := json.Unmarshal(payload, &incoming); err != nil || len(incoming.Alerts) == 0 {
		return nil, fmt.Errorf("%w: alertmanager payload", ErrInvalidPayload)
	}
	result := make([]domain.Signal, 0, len(incoming.Alerts))
	for _, alert := range incoming.Alerts {
		encoded, _ := json.Marshal(alert)
		fingerprint := alert.Fingerprint
		if fingerprint == "" {
			fingerprint = hashBytes(encoded)
		}
		observedAt := service.now().UTC()
		if alert.StartsAt != "" {
			parsed, err := time.Parse(time.RFC3339Nano, alert.StartsAt)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid startsAt", ErrInvalidPayload)
			}
			observedAt = parsed
		}
		status := alert.Status
		if status == "" {
			status = incoming.Status
		}
		if status == "" {
			status = "firing"
		}
		result = append(result, domain.Signal{
			ID:              ids.NewUUID(),
			WorkspaceID:     workspaceID,
			IntegrationID:   integrationID,
			Provider:        "alertmanager",
			ProviderEventID: hashBytes([]byte(fingerprint + "\x00" + observedAt.Format(time.RFC3339Nano) + "\x00" + status)),
			PayloadHash:     hashBytes(encoded),
			Fingerprint:     fingerprint,
			Status:          status,
			Labels:          projectLabels(alert.Labels),
			ObservedAt:      observedAt,
		})
	}
	return result, nil
}

type nightingalePayload struct {
	ID               json.RawMessage   `json:"id"`
	EventID          string            `json:"event_id"`
	Hash             string            `json:"hash"`
	TriggerTime      int64             `json:"trigger_time"`
	FirstTriggerTime int64             `json:"first_trigger_time"`
	LastEvalTime     int64             `json:"last_eval_time"`
	RuleName         string            `json:"rule_name"`
	Severity         int               `json:"severity"`
	Cluster          string            `json:"cluster"`
	TagsMap          map[string]string `json:"tags_map"`
	IsRecovered      bool              `json:"is_recovered"`
}

func (service *Service) normalizeNightingale(workspaceID, integrationID string, payload []byte) ([]domain.Signal, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: nightingale payload", ErrInvalidPayload)
	}
	var incoming []nightingalePayload
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &incoming); err != nil {
			return nil, fmt.Errorf("%w: nightingale payload", ErrInvalidPayload)
		}
	} else {
		var event nightingalePayload
		if err := json.Unmarshal(trimmed, &event); err != nil {
			return nil, fmt.Errorf("%w: nightingale payload", ErrInvalidPayload)
		}
		incoming = []nightingalePayload{event}
	}
	if len(incoming) == 0 {
		return nil, fmt.Errorf("%w: empty nightingale batch", ErrInvalidPayload)
	}
	result := make([]domain.Signal, 0, len(incoming))
	for _, event := range incoming {
		externalEventID := nightingaleEventID(event)
		if externalEventID == "" {
			return nil, fmt.Errorf("%w: nightingale event id", ErrInvalidPayload)
		}
		status := "firing"
		if event.IsRecovered {
			status = "resolved"
		}
		providerEventID := hashBytes([]byte(externalEventID + "\x00" + status))
		observedAt := service.now().UTC()
		for _, timestamp := range []int64{event.TriggerTime, event.FirstTriggerTime, event.LastEvalTime} {
			if timestamp > 0 {
				observedAt = time.Unix(timestamp, 0).UTC()
				break
			}
		}
		fingerprint := event.Hash
		if fingerprint == "" {
			fingerprint = externalEventID
		}
		labels := projectLabels(event.TagsMap)
		addProjectedLabel(labels, "alertname", event.RuleName)
		addProjectedLabel(labels, "cluster", event.Cluster)
		if event.Severity > 0 {
			addProjectedLabel(labels, "severity", strconv.Itoa(event.Severity))
		}
		encoded, _ := json.Marshal(event)
		result = append(result, domain.Signal{
			ID:              ids.NewUUID(),
			WorkspaceID:     workspaceID,
			IntegrationID:   integrationID,
			Provider:        "nightingale",
			ProviderEventID: providerEventID,
			PayloadHash:     hashBytes(encoded),
			Fingerprint:     fingerprint,
			Status:          status,
			Labels:          labels,
			ObservedAt:      observedAt,
		})
	}
	return result, nil
}

func nightingaleEventID(event nightingalePayload) string {
	if event.EventID != "" {
		return event.EventID
	}
	raw := strings.TrimSpace(string(event.ID))
	if raw == "" || raw == "null" {
		return ""
	}
	if strings.HasPrefix(raw, `"`) {
		var value string
		if json.Unmarshal(event.ID, &value) == nil {
			return value
		}
		return ""
	}
	if _, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return raw
	}
	return ""
}

var projectedLabelKeys = map[string]struct{}{
	"alertname": {}, "service": {}, "service_name": {}, "namespace": {},
	"deployment": {}, "cluster": {}, "environment": {}, "environment_id": {},
	"instance": {}, "ident": {}, "job": {}, "severity": {}, "team": {}, "owner": {},
}

func projectLabels(labels map[string]string) map[string]string {
	projected := make(map[string]string)
	for key, value := range labels {
		if _, allowed := projectedLabelKeys[key]; allowed {
			addProjectedLabel(projected, key, value)
		}
	}
	return projected
}

func addProjectedLabel(labels map[string]string, key, value string) {
	value = strings.TrimSpace(value)
	if value != "" && len(value) <= 256 {
		labels[key] = value
	}
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
