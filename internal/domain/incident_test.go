package domain_test

import (
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
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
	initialVersion := incident.Version
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
	if incident.Version != initialVersion+4 {
		t.Fatalf("Version = %d, want %d", incident.Version, initialVersion+4)
	}
}

func TestOnlyExplicitHumanFeedbackConfirmsRootCause(t *testing.T) {
	incident := domain.NewIncident("incident-1", "workspace-1", time.Now())
	hypothesis := domain.Hypothesis{
		ID:              "hypothesis-1",
		WorkspaceID:     "workspace-1",
		IncidentID:      "incident-1",
		InvestigationID: "investigation-1",
		Status:          domain.HypothesisProposed,
	}

	if err := incident.ConfirmRootCause(&hypothesis, domain.Actor{Type: domain.ActorModel, ID: "model"}); err == nil {
		t.Fatal("model confirmation error = nil, want rejection")
	}
	if err := incident.ConfirmRootCause(&hypothesis, domain.Actor{Type: domain.ActorHuman, ID: "user-1"}); err != nil {
		t.Fatalf("human confirmation error = %v", err)
	}
	if incident.ConfirmedHypothesisID != hypothesis.ID {
		t.Fatalf("ConfirmedHypothesisID = %q, want %q", incident.ConfirmedHypothesisID, hypothesis.ID)
	}
	if hypothesis.Status != domain.HypothesisConfirmed {
		t.Fatalf("hypothesis status = %s, want CONFIRMED", hypothesis.Status)
	}
}

func TestIncidentRejectsHypothesisFromAnotherIncidentOrWorkspace(t *testing.T) {
	incident := domain.NewIncident("incident-1", "workspace-1", time.Now())
	for _, hypothesis := range []domain.Hypothesis{
		{ID: "h1", WorkspaceID: "workspace-2", IncidentID: "incident-1", Status: domain.HypothesisProposed},
		{ID: "h2", WorkspaceID: "workspace-1", IncidentID: "incident-2", Status: domain.HypothesisProposed},
	} {
		if err := incident.ConfirmRootCause(&hypothesis, domain.Actor{Type: domain.ActorHuman, ID: "user-1"}); err == nil {
			t.Fatalf("ConfirmRootCause(%#v) error = nil, want ownership rejection", hypothesis)
		}
	}
}

func TestNewIncidentHasPersistableRequiredFields(t *testing.T) {
	incident := domain.NewIncident("incident-1", "workspace-1", time.Now())
	if incident.Title == "" || incident.Severity == "" {
		t.Fatalf("NewIncident() title/severity = %q/%q, want non-empty defaults", incident.Title, incident.Severity)
	}
	if err := incident.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestIncidentCreateContractRejectsPreTransitionedState(t *testing.T) {
	incident := domain.NewIncident("incident-1", "workspace-1", time.Now())
	incident.Status = domain.IncidentInvestigating
	if err := incident.ValidateForCreate(); err == nil {
		t.Fatal("ValidateForCreate() error = nil, want initial-state rejection")
	}
}

func TestIncidentRejectsBackwardTransitionTime(t *testing.T) {
	now := time.Now().UTC()
	incident := domain.NewIncident("incident-1", "workspace-1", now)
	if err := incident.TransitionAt(domain.IncidentInvestigating, now.Add(-time.Second)); err == nil {
		t.Fatal("TransitionAt() error = nil, want backward-time rejection")
	}
}
