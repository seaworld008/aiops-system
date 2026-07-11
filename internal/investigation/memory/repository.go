package memory

import (
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

var generatedIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*$`)

type Options struct {
	Clock     func() time.Time
	IDFactory func() string
}

type Repository struct {
	mu sync.RWMutex

	signals                      map[string]domain.Signal
	incidents                    map[string]domain.Incident
	activeIncidentByCorrelation  map[string]string
	signalIncident               map[string]string
	investigations               map[string]domain.Investigation
	tasks                        map[string]domain.ReadTask
	taskIDsByInvestigation       map[string][]string
	activeInvestigation          map[string]string
	investigationIdempotency     map[string]idempotencyRecord
	evidence                     map[string]domain.Evidence
	evidenceIDsByInvestigation   map[string][]string
	receipts                     map[string]domain.RunnerEvidenceReceipt
	taskCompletionIdempotency    map[string]taskCompletionRecord
	hypotheses                   map[string]domain.Hypothesis
	hypothesisIDsByInvestigation map[string][]string
	finalizeIdempotency          map[string]finalizeRecord
	feedback                     map[string]domain.Feedback
	feedbackIdempotency          map[string]idempotencyRecord

	clock     func() time.Time
	idFactory func() string
}

var _ investigation.Repository = (*Repository)(nil)

func New(options Options) (*Repository, error) {
	if options.Clock == nil || options.IDFactory == nil {
		return nil, fmt.Errorf("%w: clock and ID factory are required", investigation.ErrInvalidRequest)
	}
	if options.Clock().IsZero() {
		return nil, fmt.Errorf("%w: clock returned zero time", investigation.ErrInvalidRequest)
	}
	return &Repository{
		signals:                      make(map[string]domain.Signal),
		incidents:                    make(map[string]domain.Incident),
		activeIncidentByCorrelation:  make(map[string]string),
		signalIncident:               make(map[string]string),
		investigations:               make(map[string]domain.Investigation),
		tasks:                        make(map[string]domain.ReadTask),
		taskIDsByInvestigation:       make(map[string][]string),
		activeInvestigation:          make(map[string]string),
		investigationIdempotency:     make(map[string]idempotencyRecord),
		evidence:                     make(map[string]domain.Evidence),
		evidenceIDsByInvestigation:   make(map[string][]string),
		receipts:                     make(map[string]domain.RunnerEvidenceReceipt),
		taskCompletionIdempotency:    make(map[string]taskCompletionRecord),
		hypotheses:                   make(map[string]domain.Hypothesis),
		hypothesisIDsByInvestigation: make(map[string][]string),
		finalizeIdempotency:          make(map[string]finalizeRecord),
		feedback:                     make(map[string]domain.Feedback),
		feedbackIdempotency:          make(map[string]idempotencyRecord),
		clock:                        options.Clock,
		idFactory:                    options.IDFactory,
	}, nil
}

type idempotencyRecord struct {
	requestHash string
	resourceID  string
}

type taskCompletionRecord struct {
	requestHash string
	taskID      string
	evidenceID  string
	receiptID   string
}

type finalizeRecord struct {
	requestHash     string
	investigationID string
}

func (repository *Repository) newID() (string, error) {
	id := repository.idFactory()
	if len(id) == 0 || len(id) > 256 || !generatedIDPattern.MatchString(id) {
		return "", fmt.Errorf("%w: ID factory returned invalid ID", investigation.ErrInvalidRequest)
	}
	return id, nil
}

func scoped(workspaceID, id string) string {
	return workspaceID + "\x00" + id
}
