package memory

import (
	"fmt"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

type Options struct {
	Clock              func() time.Time
	IDFactory          func() string
	TenantResolver     func(workspaceID string) (string, error)
	TaskSpecAuthorizer investigation.TaskSpecAuthorizer
}

type Repository struct {
	mu sync.RWMutex

	signals                      map[scopeKey]domain.Signal
	signalTenants                map[scopeKey]string
	incidents                    map[scopeKey]domain.Incident
	activeIncidentByCorrelation  map[scopeKey]string
	signalIncident               map[scopeKey]signalAssociationRecord
	investigations               map[scopeKey]domain.Investigation
	tasks                        map[scopeKey]domain.ReadTask
	taskIDsByInvestigation       map[scopeKey][]string
	activeInvestigation          map[scopeKey]string
	investigationIdempotency     map[scopeKey]idempotencyRecord
	evidence                     map[scopeKey]domain.Evidence
	evidenceIDsByInvestigation   map[scopeKey][]string
	receipts                     map[scopeKey]domain.RunnerEvidenceReceipt
	taskCompletionIdempotency    map[scopeKey]taskCompletionRecord
	hypotheses                   map[scopeKey]domain.Hypothesis
	hypothesisIDsByInvestigation map[scopeKey][]string
	finalizeIdempotency          map[scopeKey]finalizeRecord
	failureIdempotency           map[scopeKey]idempotencyRecord
	feedback                     map[scopeKey]domain.Feedback
	feedbackIdempotency          map[scopeKey]idempotencyRecord
	modelStartIdempotency        map[scopeKey]modelStartRecord
	idempotencyOwners            map[scopeKey]string

	clock              func() time.Time
	idFactory          func() string
	tenantResolver     func(workspaceID string) (string, error)
	taskSpecAuthorizer investigation.TaskSpecAuthorizer
}

var _ investigation.Repository = (*Repository)(nil)

func New(options Options) (*Repository, error) {
	if options.Clock == nil || options.IDFactory == nil || options.TenantResolver == nil || options.TaskSpecAuthorizer == nil {
		return nil, fmt.Errorf("%w: trusted repository dependencies are required", investigation.ErrInvalidRequest)
	}
	if options.Clock().IsZero() {
		return nil, fmt.Errorf("%w: clock returned zero time", investigation.ErrInvalidRequest)
	}
	return &Repository{
		signals:                      make(map[scopeKey]domain.Signal),
		signalTenants:                make(map[scopeKey]string),
		incidents:                    make(map[scopeKey]domain.Incident),
		activeIncidentByCorrelation:  make(map[scopeKey]string),
		signalIncident:               make(map[scopeKey]signalAssociationRecord),
		investigations:               make(map[scopeKey]domain.Investigation),
		tasks:                        make(map[scopeKey]domain.ReadTask),
		taskIDsByInvestigation:       make(map[scopeKey][]string),
		activeInvestigation:          make(map[scopeKey]string),
		investigationIdempotency:     make(map[scopeKey]idempotencyRecord),
		evidence:                     make(map[scopeKey]domain.Evidence),
		evidenceIDsByInvestigation:   make(map[scopeKey][]string),
		receipts:                     make(map[scopeKey]domain.RunnerEvidenceReceipt),
		taskCompletionIdempotency:    make(map[scopeKey]taskCompletionRecord),
		hypotheses:                   make(map[scopeKey]domain.Hypothesis),
		hypothesisIDsByInvestigation: make(map[scopeKey][]string),
		finalizeIdempotency:          make(map[scopeKey]finalizeRecord),
		failureIdempotency:           make(map[scopeKey]idempotencyRecord),
		feedback:                     make(map[scopeKey]domain.Feedback),
		feedbackIdempotency:          make(map[scopeKey]idempotencyRecord),
		modelStartIdempotency:        make(map[scopeKey]modelStartRecord),
		idempotencyOwners:            make(map[scopeKey]string),
		clock:                        options.Clock,
		idFactory:                    options.IDFactory,
		tenantResolver:               options.TenantResolver,
		taskSpecAuthorizer:           options.TaskSpecAuthorizer,
	}, nil
}

type idempotencyRecord struct {
	requestHash string
	resourceID  string
}

type signalAssociationRecord struct {
	incidentID     string
	correlationKey string
	mappingStatus  domain.MappingStatus
	serviceID      string
	environmentID  string
}

func (record signalAssociationRecord) matches(request investigation.CorrelateSignalRequest) bool {
	return record.correlationKey == request.CorrelationKey &&
		record.mappingStatus == request.MappingStatus &&
		record.serviceID == request.ServiceID &&
		record.environmentID == request.EnvironmentID
}

type taskCompletionRecord struct {
	requestHash string
	taskID      string
	evidenceID  string
	receiptID   string
}

type finalizeRecord struct {
	requestHash string
	result      investigation.FinalizeInvestigationResult
}

type modelStartRecord struct {
	requestHash string
	result      investigation.StartModelResult
}

func (repository *Repository) newID() (string, error) {
	id := repository.idFactory()
	if !domain.ValidResourceID(id) {
		return "", fmt.Errorf("%w: ID factory returned invalid ID", investigation.ErrInvalidRequest)
	}
	return id, nil
}

type scopeKey struct {
	workspaceID string
	resourceID  string
}

func scoped(workspaceID, id string) scopeKey {
	return scopeKey{workspaceID: workspaceID, resourceID: id}
}

func validResourceScope(workspaceID string, resourceIDs ...string) bool {
	if !domain.ValidResourceID(workspaceID) {
		return false
	}
	for _, resourceID := range resourceIDs {
		if !domain.ValidResourceID(resourceID) {
			return false
		}
	}
	return true
}

func (repository *Repository) idempotencyOwnerMatches(key scopeKey, operation string) bool {
	owner, exists := repository.idempotencyOwners[key]
	return !exists || owner == operation
}

func (repository *Repository) bindIdempotencyOwner(key scopeKey, operation string) {
	repository.idempotencyOwners[key] = operation
}
