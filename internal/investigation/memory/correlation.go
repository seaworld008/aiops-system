package memory

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/store"
)

func (repository *Repository) RegisterSignal(ctx context.Context, signal domain.Signal) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	normalized, err := investigation.NormalizeSignalForReplay(signal)
	if err != nil {
		return false, err
	}
	signal = normalized
	key := scoped(signal.WorkspaceID, signal.ID)
	repository.mu.RLock()
	existing, exists := repository.signals[key]
	storedTenant, hasTenant := repository.signalTenants[key]
	repository.mu.RUnlock()
	if exists {
		if !hasTenant || !domain.ValidResourceID(storedTenant) {
			return false, store.ErrScopeViolation
		}
		if reflect.DeepEqual(existing, signal) {
			return false, nil
		}
		return false, store.ErrIdempotencyConflict
	}
	tenantID, err := repository.tenantResolver(signal.WorkspaceID)
	if err != nil || !domain.ValidResourceID(tenantID) {
		return false, fmt.Errorf("%w: trusted tenant resolution failed", investigation.ErrInvalidRequest)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if existing, exists := repository.signals[key]; exists {
		storedTenant, hasTenant := repository.signalTenants[key]
		if !hasTenant || !domain.ValidResourceID(storedTenant) {
			return false, store.ErrScopeViolation
		}
		if reflect.DeepEqual(existing, signal) {
			return false, nil
		}
		return false, store.ErrIdempotencyConflict
	}
	if err := investigation.ValidateNewSignalTime(signal, repository.clock()); err != nil {
		return false, err
	}
	repository.signals[key] = signal
	repository.signalTenants[key] = tenantID
	return true, nil
}

func (repository *Repository) GetSignal(ctx context.Context, workspaceID, signalID string) (domain.Signal, error) {
	if err := ctx.Err(); err != nil {
		return domain.Signal{}, err
	}
	if !validResourceScope(workspaceID, signalID) {
		return domain.Signal{}, fmt.Errorf("%w: workspace and signal IDs are required", investigation.ErrInvalidRequest)
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	signal, exists := repository.signals[scoped(workspaceID, signalID)]
	if !exists {
		return domain.Signal{}, store.ErrNotFound
	}
	return cloneSignal(signal), nil
}

func (repository *Repository) GetRegisteredSignal(ctx context.Context, signalID string) (investigation.RegisteredSignal, error) {
	if ctx == nil {
		return investigation.RegisteredSignal{}, fmt.Errorf("%w: context is required", investigation.ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return investigation.RegisteredSignal{}, err
	}
	if !investigation.ValidPersistentSignalID(signalID) {
		return investigation.RegisteredSignal{}, fmt.Errorf("%w: invalid global signal ID", investigation.ErrInvalidRequest)
	}
	repository.mu.RLock()
	var found domain.Signal
	var tenantID string
	matches := 0
	for key, signal := range repository.signals {
		if key.resourceID == signalID {
			found = cloneSignal(signal)
			tenantID = repository.signalTenants[key]
			matches++
		}
	}
	repository.mu.RUnlock()
	if matches == 0 {
		return investigation.RegisteredSignal{}, store.ErrNotFound
	}
	if matches != 1 {
		return investigation.RegisteredSignal{}, store.ErrScopeViolation
	}
	if !domain.ValidResourceID(tenantID) {
		return investigation.RegisteredSignal{}, store.ErrScopeViolation
	}
	return investigation.RegisteredSignal{
		TenantID: tenantID, WorkspaceID: found.WorkspaceID, Signal: found,
	}, nil
}

func (repository *Repository) CorrelateSignal(ctx context.Context, request investigation.CorrelateSignalRequest) (investigation.CorrelateSignalResult, error) {
	if err := ctx.Err(); err != nil {
		return investigation.CorrelateSignalResult{}, err
	}
	if !domain.ValidResourceID(request.WorkspaceID) || !domain.ValidResourceID(request.SignalID) || !domain.ValidCorrelationKey(request.CorrelationKey) ||
		!validMapping(request.MappingStatus, request.ServiceID, request.EnvironmentID) ||
		(request.ExpectedSignalHash != "" && !domain.ValidSHA256Hex(request.ExpectedSignalHash)) {
		return investigation.CorrelateSignalResult{}, fmt.Errorf("%w: invalid signal correlation", investigation.ErrInvalidRequest)
	}
	signalKey := scoped(request.WorkspaceID, request.SignalID)
	repository.mu.RLock()
	tenantID, tenantFound := repository.signalTenants[signalKey]
	if !tenantFound || !domain.ValidResourceID(tenantID) {
		repository.mu.RUnlock()
		return investigation.CorrelateSignalResult{}, store.ErrScopeViolation
	}
	if !repository.signalSnapshotMatchesLocked(signalKey, request.ExpectedSignalHash) {
		repository.mu.RUnlock()
		return investigation.CorrelateSignalResult{}, store.ErrScopeViolation
	}
	result, err, handled := repository.correlationReplayLocked(signalKey, request)
	repository.mu.RUnlock()
	if handled {
		return result, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID, tenantFound = repository.signalTenants[signalKey]
	if !tenantFound || !domain.ValidResourceID(tenantID) {
		return investigation.CorrelateSignalResult{}, store.ErrScopeViolation
	}
	if !repository.signalSnapshotMatchesLocked(signalKey, request.ExpectedSignalHash) {
		return investigation.CorrelateSignalResult{}, store.ErrScopeViolation
	}
	result, err, handled = repository.correlationReplayLocked(signalKey, request)
	if handled {
		return result, err
	}
	signal := repository.signals[signalKey]
	now := repository.clock().UTC()
	if now.IsZero() {
		return investigation.CorrelateSignalResult{}, fmt.Errorf("%w: clock returned zero time", investigation.ErrInvalidRequest)
	}

	correlationKey := scoped(request.WorkspaceID, request.CorrelationKey)
	incidentID := repository.activeIncidentByCorrelation[correlationKey]
	incident, active := repository.incidents[scoped(request.WorkspaceID, incidentID)]
	if active && !isActiveIncident(incident.Status) {
		delete(repository.activeIncidentByCorrelation, correlationKey)
		active = false
	}
	if active && incident.TenantID != tenantID {
		return investigation.CorrelateSignalResult{}, store.ErrScopeViolation
	}
	if active && (incident.CorrelationKey != request.CorrelationKey || incident.MappingStatus != request.MappingStatus ||
		incident.ServiceID != request.ServiceID || incident.EnvironmentID != request.EnvironmentID) {
		return investigation.CorrelateSignalResult{}, store.ErrScopeViolation
	}
	if !active && signal.Status == "resolved" {
		repository.signalIncident[signalKey] = signalAssociationRecord{
			correlationKey: request.CorrelationKey, mappingStatus: request.MappingStatus,
			serviceID: request.ServiceID, environmentID: request.EnvironmentID,
		}
		return investigation.CorrelateSignalResult{}, nil
	}

	created := false
	if !active {
		incidentID, err := repository.newID()
		if err != nil {
			return investigation.CorrelateSignalResult{}, err
		}
		if _, duplicate := repository.incidents[scoped(request.WorkspaceID, incidentID)]; duplicate {
			return investigation.CorrelateSignalResult{}, fmt.Errorf("%w: ID factory returned duplicate incident ID", investigation.ErrInvalidRequest)
		}
		openedAt := signal.ObservedAt.UTC()
		updatedAt := laterTime(now, openedAt)
		incident = domain.NewIncidentForTenant(incidentID, tenantID, request.WorkspaceID, openedAt)
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
		incident.UpdatedAt = latestTime(incident.UpdatedAt, now, incident.LastSignalAt)
		incident.Version++
		if err := incident.Validate(); err != nil {
			return investigation.CorrelateSignalResult{}, fmt.Errorf("%w: %v", investigation.ErrInvalidRequest, err)
		}
		repository.incidents[scoped(request.WorkspaceID, incident.ID)] = incident
	}
	repository.signalIncident[signalKey] = signalAssociationRecord{
		incidentID: incident.ID, correlationKey: request.CorrelationKey, mappingStatus: request.MappingStatus,
		serviceID: request.ServiceID, environmentID: request.EnvironmentID,
	}
	return investigation.CorrelateSignalResult{
		Incident: cloneIncident(incident), Created: created, Associated: true, Counted: true,
	}, nil
}

func (repository *Repository) signalSnapshotMatchesLocked(signalKey scopeKey, expected string) bool {
	if expected == "" {
		return true
	}
	signal, exists := repository.signals[signalKey]
	if !exists {
		return false
	}
	tenantID, exists := repository.signalTenants[signalKey]
	if !exists {
		return false
	}
	actual, err := investigation.RegisteredSignalSnapshotHash(investigation.RegisteredSignal{
		TenantID: tenantID, WorkspaceID: signal.WorkspaceID, Signal: signal,
	})
	return err == nil && actual == expected
}

func (repository *Repository) correlationReplayLocked(signalKey scopeKey, request investigation.CorrelateSignalRequest) (investigation.CorrelateSignalResult, error, bool) {
	if _, exists := repository.signals[signalKey]; !exists {
		return investigation.CorrelateSignalResult{}, store.ErrNotFound, true
	}
	association, associated := repository.signalIncident[signalKey]
	if !associated {
		return investigation.CorrelateSignalResult{}, nil, false
	}
	if !association.matches(request) {
		return investigation.CorrelateSignalResult{}, store.ErrIdempotencyConflict, true
	}
	if association.incidentID == "" {
		return investigation.CorrelateSignalResult{}, nil, true
	}
	incident, exists := repository.incidents[scoped(request.WorkspaceID, association.incidentID)]
	if !exists {
		return investigation.CorrelateSignalResult{}, store.ErrNotFound, true
	}
	return investigation.CorrelateSignalResult{
		Incident: cloneIncident(incident), Associated: true,
	}, nil, true
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
