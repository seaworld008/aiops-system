package domain

import (
	"fmt"
	"time"
)

type IncidentStatus string

const (
	IncidentOpen          IncidentStatus = "OPEN"
	IncidentInvestigating IncidentStatus = "INVESTIGATING"
	IncidentMitigating    IncidentStatus = "MITIGATING"
	IncidentResolved      IncidentStatus = "RESOLVED"
	IncidentClosed        IncidentStatus = "CLOSED"
)

var incidentTransitions = map[IncidentStatus]IncidentStatus{
	IncidentOpen:          IncidentInvestigating,
	IncidentInvestigating: IncidentMitigating,
	IncidentMitigating:    IncidentResolved,
	IncidentResolved:      IncidentClosed,
}

type Incident struct {
	ID                    string
	WorkspaceID           string
	ServiceID             string
	EnvironmentID         string
	Severity              string
	Title                 string
	Status                IncidentStatus
	ConfirmedHypothesisID string
	OpenedAt              time.Time
	UpdatedAt             time.Time
	Version               int64
}

func NewIncident(id, workspaceID string, now time.Time) Incident {
	return Incident{
		ID:          id,
		WorkspaceID: workspaceID,
		Severity:    "UNKNOWN",
		Title:       "Unclassified operational incident",
		Status:      IncidentOpen,
		OpenedAt:    now,
		UpdatedAt:   now,
		Version:     1,
	}
}

func (incident Incident) Validate() error {
	if incident.ID == "" || incident.WorkspaceID == "" || incident.Severity == "" || incident.Title == "" {
		return fmt.Errorf("incident id, workspace id, severity and title are required")
	}
	if incident.OpenedAt.IsZero() || incident.UpdatedAt.IsZero() || incident.UpdatedAt.Before(incident.OpenedAt) {
		return fmt.Errorf("incident timestamps are invalid")
	}
	if incident.Version <= 0 {
		return fmt.Errorf("incident version must be positive")
	}
	switch incident.Status {
	case IncidentOpen, IncidentInvestigating, IncidentMitigating, IncidentResolved, IncidentClosed:
	default:
		return fmt.Errorf("invalid incident status %q", incident.Status)
	}
	return nil
}

func (incident Incident) ValidateForCreate() error {
	if err := incident.Validate(); err != nil {
		return err
	}
	if incident.Status != IncidentOpen || incident.Version != 1 || incident.ConfirmedHypothesisID != "" {
		return fmt.Errorf("new incident must be OPEN at version 1 without a confirmed hypothesis")
	}
	return nil
}

func (incident *Incident) Transition(next IncidentStatus) error {
	return incident.TransitionAt(next, time.Now().UTC())
}

func (incident *Incident) TransitionAt(next IncidentStatus, now time.Time) error {
	want, ok := incidentTransitions[incident.Status]
	if !ok || want != next {
		return fmt.Errorf("invalid incident transition %s -> %s", incident.Status, next)
	}
	if now.IsZero() || now.Before(incident.UpdatedAt) {
		return fmt.Errorf("incident transition time cannot move backward")
	}
	incident.Status = next
	incident.UpdatedAt = now.UTC()
	incident.Version++
	return nil
}

func (incident *Incident) ConfirmRootCause(hypothesis *Hypothesis, actor Actor) error {
	return incident.ConfirmRootCauseAt(hypothesis, actor, time.Now().UTC())
}

func (incident *Incident) ConfirmRootCauseAt(hypothesis *Hypothesis, actor Actor, now time.Time) error {
	if actor.Type != ActorHuman || actor.ID == "" {
		return fmt.Errorf("root cause confirmation requires an authenticated human")
	}
	if hypothesis == nil || hypothesis.ID == "" || hypothesis.Status != HypothesisProposed {
		return fmt.Errorf("only a proposed hypothesis can be confirmed")
	}
	if hypothesis.WorkspaceID != incident.WorkspaceID || hypothesis.IncidentID != incident.ID {
		return fmt.Errorf("hypothesis does not belong to this incident")
	}
	if now.IsZero() || now.Before(incident.UpdatedAt) {
		return fmt.Errorf("root cause confirmation time cannot move backward")
	}
	hypothesis.Status = HypothesisConfirmed
	incident.ConfirmedHypothesisID = hypothesis.ID
	incident.UpdatedAt = now.UTC()
	incident.Version++
	return nil
}
