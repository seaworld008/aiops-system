package domain_test

import (
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/domain"
)

func TestIncidentRejectsInvalidStateTransition(t *testing.T) {
	incident := domain.NewIncident("incident-1", "workspace-1", time.Now())

	if err := incident.Transition(domain.IncidentResolved); err == nil {
		t.Fatal("Transition(OPEN -> RESOLVED) error = nil, want invalid transition")
	}
	if incident.Status != domain.IncidentOpen {
		t.Fatalf("status changed to %s after rejected transition", incident.Status)
	}
}

func TestIncidentAllowsOrderedLifecycle(t *testing.T) {
	incident := domain.NewIncident("incident-1", "workspace-1", time.Now())
	for _, next := range []domain.IncidentStatus{
		domain.IncidentInvestigating,
		domain.IncidentMitigating,
		domain.IncidentResolved,
		domain.IncidentClosed,
	} {
		if err := incident.Transition(next); err != nil {
			t.Fatalf("Transition(%s) error = %v", next, err)
		}
	}
}

func TestOnlyExplicitHumanFeedbackConfirmsRootCause(t *testing.T) {
	incident := domain.NewIncident("incident-1", "workspace-1", time.Now())
	hypothesis := domain.Hypothesis{
		ID:              "hypothesis-1",
		InvestigationID: "investigation-1",
		Status:          domain.HypothesisProposed,
	}

	if err := incident.ConfirmRootCause(hypothesis, domain.Actor{Type: domain.ActorModel, ID: "model"}); err == nil {
		t.Fatal("model confirmation error = nil, want rejection")
	}
	if err := incident.ConfirmRootCause(hypothesis, domain.Actor{Type: domain.ActorHuman, ID: "user-1"}); err != nil {
		t.Fatalf("human confirmation error = %v", err)
	}
	if incident.ConfirmedHypothesisID != hypothesis.ID {
		t.Fatalf("ConfirmedHypothesisID = %q, want %q", incident.ConfirmedHypothesisID, hypothesis.ID)
	}
}
