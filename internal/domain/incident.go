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
	Status                IncidentStatus
	ConfirmedHypothesisID string
	OpenedAt              time.Time
	UpdatedAt             time.Time
}

func NewIncident(id, workspaceID string, now time.Time) Incident {
	return Incident{
		ID:          id,
		WorkspaceID: workspaceID,
		Status:      IncidentOpen,
		OpenedAt:    now,
		UpdatedAt:   now,
	}
}

func (incident *Incident) Transition(next IncidentStatus) error {
	want, ok := incidentTransitions[incident.Status]
	if !ok || want != next {
		return fmt.Errorf("invalid incident transition %s -> %s", incident.Status, next)
	}
	incident.Status = next
	incident.UpdatedAt = time.Now().UTC()
	return nil
}

func (incident *Incident) ConfirmRootCause(hypothesis *Hypothesis, actor Actor) error {
	if actor.Type != ActorHuman || actor.ID == "" {
		return fmt.Errorf("root cause confirmation requires an authenticated human")
	}
	if hypothesis == nil || hypothesis.ID == "" || hypothesis.Status != HypothesisProposed {
		return fmt.Errorf("only a proposed hypothesis can be confirmed")
	}
	if hypothesis.WorkspaceID != incident.WorkspaceID || hypothesis.IncidentID != incident.ID {
		return fmt.Errorf("hypothesis does not belong to this incident")
	}
	hypothesis.Status = HypothesisConfirmed
	incident.ConfirmedHypothesisID = hypothesis.ID
	incident.UpdatedAt = time.Now().UTC()
	return nil
}
