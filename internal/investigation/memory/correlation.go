package memory

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

const (
	maxSignalLabels     = 64
	maxSignalLabelValue = 512
)

var signalLabelKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}$`)

func (repository *Repository) RegisterSignal(ctx context.Context, signal domain.Signal) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !validInvestigationSignal(signal) {
		return false, fmt.Errorf("%w: invalid signal scope", investigation.ErrInvalidRequest)
	}
	if err := signal.Validate(); err != nil {
		return false, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, err)
	}
	signal = cloneSignal(signal)
	key := scoped(signal.WorkspaceID, signal.ID)
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if existing, exists := repository.signals[key]; exists {
		if reflect.DeepEqual(existing, signal) {
			return false, nil
		}
		return false, store.ErrIdempotencyConflict
	}
	repository.signals[key] = signal
	return true, nil
}

func validInvestigationSignal(signal domain.Signal) bool {
	if !domain.ValidResourceID(signal.WorkspaceID) || !domain.ValidResourceID(signal.ID) ||
		!domain.ValidResourceID(signal.IntegrationID) || !domain.ValidSHA256Hex(signal.PayloadHash) ||
		len(signal.Labels) > maxSignalLabels {
		return false
	}
	for key, value := range signal.Labels {
		if !signalLabelKeyPattern.MatchString(key) || len(value) > maxSignalLabelValue || !utf8.ValidString(value) ||
			strings.IndexFunc(value, unicode.IsControl) >= 0 || !domain.ValidSafeMetadata(key, value) {
			return false
		}
	}
	return true
}

func (repository *Repository) CorrelateSignal(ctx context.Context, request investigation.CorrelateSignalRequest) (investigation.CorrelateSignalResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.CorrelateSignalResult{}, err
	}
	if !domain.ValidResourceID(request.WorkspaceID) || !domain.ValidResourceID(request.SignalID) || !domain.ValidCorrelationKey(request.CorrelationKey) ||
		!validMapping(request.MappingStatus, request.ServiceID, request.EnvironmentID) {
		return investigation.CorrelateSignalResult{}, fmt.Errorf("%w: invalid signal correlation", investigation.ErrInvalidRequest)
	}
	now := repository.clock().UTC()
	if now.IsZero() {
		return investigation.CorrelateSignalResult{}, fmt.Errorf("%w: clock returned zero time", investigation.ErrInvalidRequest)
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	signalKey := scoped(request.WorkspaceID, request.SignalID)
	signal, exists := repository.signals[signalKey]
	if !exists {
		return investigation.CorrelateSignalResult{}, store.ErrNotFound
	}
	if incidentID, associated := repository.signalIncident[signalKey]; associated {
		incident, incidentExists := repository.incidents[scoped(request.WorkspaceID, incidentID)]
		if !incidentExists {
			return investigation.CorrelateSignalResult{}, store.ErrNotFound
		}
		return investigation.CorrelateSignalResult{
			Incident: cloneIncident(incident), Associated: true,
		}, nil
	}

	correlationKey := scoped(request.WorkspaceID, request.CorrelationKey)
	incidentID := repository.activeIncidentByCorrelation[correlationKey]
	incident, active := repository.incidents[scoped(request.WorkspaceID, incidentID)]
	if active && !isActiveIncident(incident.Status) {
		delete(repository.activeIncidentByCorrelation, correlationKey)
		active = false
	}
	if !active && signal.Status == "resolved" {
		return investigation.CorrelateSignalResult{}, nil
	}

	created := false
	if !active {
		incidentID, err := repository.newID()
		if err != nil {
			return investigation.CorrelateSignalResult{}, err
		}
		openedAt := signal.ObservedAt.UTC()
		updatedAt := laterTime(now, openedAt)
		incident = domain.NewIncident(incidentID, request.WorkspaceID, openedAt)
		incident.ServiceID = request.ServiceID
		incident.EnvironmentID = request.EnvironmentID
		incident.CorrelationKey = request.CorrelationKey
		incident.MappingStatus = request.MappingStatus
		incident.LastSignalAt = openedAt
		incident.UpdatedAt = updatedAt
		incident.SignalCount = 1
		if err := incident.ValidateForCreate(); err != nil {
			return investigation.CorrelateSignalResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, err)
		}
		repository.incidents[scoped(request.WorkspaceID, incident.ID)] = incident
		repository.activeIncidentByCorrelation[correlationKey] = incident.ID
		created = true
	} else {
		incident.SignalCount++
		if signal.ObservedAt.Before(incident.OpenedAt) {
			incident.OpenedAt = signal.ObservedAt.UTC()
		}
		if signal.ObservedAt.After(incident.LastSignalAt) {
			incident.LastSignalAt = signal.ObservedAt.UTC()
		}
		incident.UpdatedAt = laterTime(now, incident.LastSignalAt)
		incident.Version++
		if err := incident.Validate(); err != nil {
			return investigation.CorrelateSignalResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, err)
		}
		repository.incidents[scoped(request.WorkspaceID, incident.ID)] = incident
	}
	repository.signalIncident[signalKey] = incident.ID
	return investigation.CorrelateSignalResult{
		Incident: cloneIncident(incident), Created: created, Associated: true, Counted: true,
	}, nil
}

func (repository *Repository) GetIncident(ctx context.Context, workspaceID, incidentID string) (domain.Incident, error) {
	if err := ctx.Err(); err != nil {
		return domain.Incident{}, err
	}
	if !domain.ValidResourceID(workspaceID) || !domain.ValidResourceID(incidentID) {
		return domain.Incident{}, fmt.Errorf("%w: workspace and incident IDs are required", investigation.ErrInvalidRequest)
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	incident, exists := repository.incidents[scoped(workspaceID, incidentID)]
	if !exists {
		return domain.Incident{}, store.ErrNotFound
	}
	return cloneIncident(incident), nil
}

func (repository *Repository) ListIncidents(ctx context.Context, request investigation.ListIncidentsRequest) ([]domain.Incident, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !domain.ValidResourceID(request.WorkspaceID) {
		return nil, fmt.Errorf("%w: workspace ID is required", investigation.ErrInvalidRequest)
	}
	statuses := make(map[domain.IncidentStatus]struct{}, len(request.Statuses))
	for _, status := range request.Statuses {
		if !validIncidentStatus(status) {
			return nil, fmt.Errorf("%w: invalid incident status filter", investigation.ErrInvalidRequest)
		}
		statuses[status] = struct{}{}
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	items := make([]domain.Incident, 0)
	for _, incident := range repository.incidents {
		if incident.WorkspaceID != request.WorkspaceID {
			continue
		}
		if len(statuses) > 0 {
			if _, wanted := statuses[incident.Status]; !wanted {
				continue
			}
		}
		items = append(items, cloneIncident(incident))
	}
	sort.Slice(items, func(left, right int) bool {
		if !items[left].OpenedAt.Equal(items[right].OpenedAt) {
			return items[left].OpenedAt.Before(items[right].OpenedAt)
		}
		return items[left].ID < items[right].ID
	})
	return items, nil
}

func validMapping(status domain.MappingStatus, serviceID, environmentID string) bool {
	switch status {
	case domain.MappingExact:
		return domain.ValidResourceID(serviceID) && domain.ValidResourceID(environmentID)
	case domain.MappingAmbiguous, domain.MappingUnresolved:
		return (serviceID == "" || domain.ValidResourceID(serviceID)) &&
			(environmentID == "" || domain.ValidResourceID(environmentID))
	default:
		return false
	}
}

func isActiveIncident(status domain.IncidentStatus) bool {
	return status == domain.IncidentOpen || status == domain.IncidentInvestigating || status == domain.IncidentMitigating
}

func validIncidentStatus(status domain.IncidentStatus) bool {
	switch status {
	case domain.IncidentOpen, domain.IncidentInvestigating, domain.IncidentMitigating,
		domain.IncidentResolved, domain.IncidentClosed:
		return true
	default:
		return false
	}
}
