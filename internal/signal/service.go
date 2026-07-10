package signal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aiops-system/control-plane/internal/domain"
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
	payloadHash := hashBytes(payload)
	result := make([]domain.Signal, 0, len(incoming.Alerts))
	for _, alert := range incoming.Alerts {
		fingerprint := alert.Fingerprint
		if fingerprint == "" {
			encoded, _ := json.Marshal(alert)
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
		result = append(result, domain.Signal{
			ID:              newID(),
			WorkspaceID:     workspaceID,
			IntegrationID:   integrationID,
			Provider:        "alertmanager",
			ProviderEventID: fingerprint + "/" + observedAt.Format(time.RFC3339Nano) + "/" + status,
			PayloadHash:     payloadHash,
			Fingerprint:     fingerprint,
			ObservedAt:      observedAt,
		})
	}
	return result, nil
}

type nightingalePayload struct {
	EventID     string `json:"event_id"`
	Hash        string `json:"hash"`
	TriggerTime int64  `json:"trigger_time"`
}

func (service *Service) normalizeNightingale(workspaceID, integrationID string, payload []byte) ([]domain.Signal, error) {
	var incoming nightingalePayload
	if err := json.Unmarshal(payload, &incoming); err != nil || incoming.EventID == "" {
		return nil, fmt.Errorf("%w: nightingale payload", ErrInvalidPayload)
	}
	observedAt := service.now().UTC()
	if incoming.TriggerTime > 0 {
		observedAt = time.Unix(incoming.TriggerTime, 0).UTC()
	}
	fingerprint := incoming.Hash
	if fingerprint == "" {
		fingerprint = incoming.EventID
	}
	return []domain.Signal{{
		ID:              newID(),
		WorkspaceID:     workspaceID,
		IntegrationID:   integrationID,
		Provider:        "nightingale",
		ProviderEventID: incoming.EventID,
		PayloadHash:     hashBytes(payload),
		Fingerprint:     fingerprint,
		ObservedAt:      observedAt,
	}}, nil
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func newID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}
