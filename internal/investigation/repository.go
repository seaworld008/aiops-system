package investigation

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
)

var (
	ErrInvalidRequest    = errors.New("invalid investigation repository request")
	ErrInvalidTransition = errors.New("invalid investigation state transition")
)

type TaskSpec struct {
	Key         string
	ConnectorID string
	Operation   string
	Input       json.RawMessage
}

type CorrelateSignalRequest struct {
	WorkspaceID    string
	SignalID       string
	CorrelationKey string
	ServiceID      string
	EnvironmentID  string
	MappingStatus  domain.MappingStatus
}

type CorrelateSignalResult struct {
	Incident   domain.Incident
	Created    bool
	Associated bool
	Counted    bool
}

type CreateOrGetInvestigationRequest struct {
	WorkspaceID    string
	IncidentID     string
	IdempotencyKey string
	Tasks          []TaskSpec
}

type CreateOrGetInvestigationResult struct {
	Investigation domain.Investigation
	Tasks         []domain.ReadTask
	Created       bool
}

type ListIncidentsRequest struct {
	WorkspaceID string
	Statuses    []domain.IncidentStatus
}

type ListInvestigationsRequest struct {
	WorkspaceID string
	IncidentID  string
	Statuses    []domain.InvestigationStatus
}

type ListTasksRequest struct {
	WorkspaceID     string
	InvestigationID string
	Statuses        []domain.ReadTaskStatus
}

type ListEvidenceRequest struct {
	WorkspaceID     string
	InvestigationID string
	TaskID          string
}

type ListHypothesesRequest struct {
	WorkspaceID     string
	InvestigationID string
}

type EvidenceInput struct {
	Payload     json.RawMessage
	ContentHash string
	Attributes  map[string]string
	CollectedAt time.Time
}

type CompleteTaskRequest struct {
	WorkspaceID     string
	InvestigationID string
	TaskID          string
	RunnerID        string
	IdempotencyKey  string
	Status          domain.ReadTaskStatus
	Evidence        *EvidenceInput
	FailureCode     string
}

type CompleteTaskResult struct {
	Task     domain.ReadTask
	Evidence *domain.Evidence
	Receipt  domain.RunnerEvidenceReceipt
	Replayed bool
}

type HypothesisSpec struct {
	Rank         int
	Confidence   float64
	Summary      string
	Proposal     json.RawMessage
	ProposalHash string
	Unknowns     []string
	EvidenceIDs  []string
}

type FinalizeInvestigationRequest struct {
	WorkspaceID      string
	InvestigationID  string
	IdempotencyKey   string
	Status           domain.InvestigationStatus
	ModelStatus      domain.ModelStatus
	FailureCode      string
	ModelFailureCode string
	Hypotheses       []HypothesisSpec
}

type FinalizeInvestigationResult struct {
	Investigation domain.Investigation
	Hypotheses    []domain.Hypothesis
	Replayed      bool
}

type FailInvestigationRequest struct {
	WorkspaceID     string
	InvestigationID string
	IdempotencyKey  string
	FailureCode     string
}

type FailInvestigationResult struct {
	Investigation domain.Investigation
	Replayed      bool
}

type StartModelRequest struct {
	WorkspaceID     string
	InvestigationID string
	IdempotencyKey  string
}

type StartModelResult struct {
	Investigation domain.Investigation
	Replayed      bool
}

type RecordFeedbackRequest struct {
	WorkspaceID     string
	IncidentID      string
	InvestigationID string
	HypothesisID    string
	Actor           domain.Actor
	Verdict         domain.FeedbackVerdict
	Details         json.RawMessage
	IdempotencyKey  string
}

type RecordFeedbackResult struct {
	Feedback domain.Feedback
	Created  bool
}

type Repository interface {
	RegisterSignal(context.Context, domain.Signal) (bool, error)
	CorrelateSignal(context.Context, CorrelateSignalRequest) (CorrelateSignalResult, error)
	CreateOrGetInvestigation(context.Context, CreateOrGetInvestigationRequest) (CreateOrGetInvestigationResult, error)

	GetIncident(context.Context, string, string) (domain.Incident, error)
	ListIncidents(context.Context, ListIncidentsRequest) ([]domain.Incident, error)
	GetInvestigation(context.Context, string, string) (domain.Investigation, error)
	ListInvestigations(context.Context, ListInvestigationsRequest) ([]domain.Investigation, error)
	GetTask(context.Context, string, string) (domain.ReadTask, error)
	ListTasks(context.Context, ListTasksRequest) ([]domain.ReadTask, error)
	GetEvidence(context.Context, string, string) (domain.Evidence, error)
	ListEvidence(context.Context, ListEvidenceRequest) ([]domain.Evidence, error)
	GetHypothesis(context.Context, string, string) (domain.Hypothesis, error)
	ListHypotheses(context.Context, ListHypothesesRequest) ([]domain.Hypothesis, error)

	CompleteTask(context.Context, CompleteTaskRequest) (CompleteTaskResult, error)
	StartModel(context.Context, StartModelRequest) (StartModelResult, error)
	FinalizeInvestigation(context.Context, FinalizeInvestigationRequest) (FinalizeInvestigationResult, error)
	FailInvestigation(context.Context, FailInvestigationRequest) (FailInvestigationResult, error)
	RecordFeedback(context.Context, RecordFeedbackRequest) (RecordFeedbackResult, error)
}
