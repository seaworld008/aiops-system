package domain_test

import (
	"strings"
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
	now := time.Date(2026, 7, 12, 14, 0, 0, 0, time.UTC)
	incident := domain.NewIncident("incident-1", "workspace-1", now)
	hypothesis := validRootCauseHypothesis(now, "hypothesis-1", "workspace-1", "incident-1")

	if err := incident.ConfirmRootCauseAt(&hypothesis, domain.Actor{Type: domain.ActorModel, ID: "model"}, now); err == nil {
		t.Fatal("model confirmation error = nil, want rejection")
	}
	if err := incident.ConfirmRootCauseAt(&hypothesis, domain.Actor{Type: domain.ActorHuman, ID: "user-1"}, now); err != nil {
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
	now := time.Date(2026, 7, 12, 14, 0, 0, 0, time.UTC)
	incident := domain.NewIncident("incident-1", "workspace-1", now)
	for _, hypothesis := range []domain.Hypothesis{
		validRootCauseHypothesis(now, "h1", "workspace-2", "incident-1"),
		validRootCauseHypothesis(now, "h2", "workspace-1", "incident-2"),
	} {
		if err := incident.ConfirmRootCauseAt(&hypothesis, domain.Actor{Type: domain.ActorHuman, ID: "user-1"}, now); err == nil {
			t.Fatalf("ConfirmRootCause(%#v) error = nil, want ownership rejection", hypothesis)
		}
	}
}

func validRootCauseHypothesis(now time.Time, id, workspaceID, incidentID string) domain.Hypothesis {
	proposal := []byte(`{"summary":"evidence-backed root cause"}`)
	return domain.Hypothesis{
		ID: id, WorkspaceID: workspaceID, IncidentID: incidentID, InvestigationID: "investigation-1",
		Status: domain.HypothesisProposed, Rank: 1, Confidence: 0.8, Summary: "Evidence-backed root cause",
		Proposal: proposal, ProposalHash: sha256Hex(proposal), EvidenceIDs: []string{"evidence-1"}, CreatedAt: now,
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

func TestIncidentValidatesCorrelationMetadataAsOneConsistentUnit(t *testing.T) {
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	incident := domain.NewIncident("incident-1", "workspace-1", now)
	incident.CorrelationKey = "payments:production:latency"
	incident.MappingStatus = domain.MappingExact
	incident.ServiceID = "payments"
	incident.EnvironmentID = "production"
	incident.LastSignalAt = now
	incident.SignalCount = 1

	if err := incident.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want valid correlation metadata", err)
	}

	incident.SignalCount = 0
	if err := incident.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want inconsistent signal count rejection")
	}
}

func TestIncidentRejectsNonCanonicalCorrelationKeysAndInconsistentSignalTimes(t *testing.T) {
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	valid := domain.NewIncident("incident-1", "workspace-1", now)
	valid.CorrelationKey = "payments:production:latency"
	valid.LastSignalAt = now
	valid.SignalCount = 1

	for name, mutate := range map[string]func(*domain.Incident){
		"uppercase":  func(incident *domain.Incident) { incident.CorrelationKey = "Payments:latency" },
		"whitespace": func(incident *domain.Incident) { incident.CorrelationKey = " payments:latency" },
		"oversized":  func(incident *domain.Incident) { incident.CorrelationKey = strings.Repeat("a", 513) },
		"before opened": func(incident *domain.Incident) {
			incident.LastSignalAt = incident.OpenedAt.Add(-time.Nanosecond)
		},
		"after updated": func(incident *domain.Incident) {
			incident.LastSignalAt = incident.UpdatedAt.Add(time.Nanosecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			incident := valid
			mutate(&incident)
			if err := incident.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want correlation contract rejection")
			}
		})
	}
}

func TestIncidentExactMappingRequiresServiceAndEnvironment(t *testing.T) {
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	incident := domain.NewIncident("incident-1", "workspace-1", now)
	incident.CorrelationKey = "payments:production:latency"
	incident.MappingStatus = domain.MappingExact
	incident.LastSignalAt = now
	incident.SignalCount = 1
	if err := incident.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want incomplete EXACT mapping rejection")
	}
	incident.ServiceID = "payments"
	incident.EnvironmentID = "production"
	if err := incident.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want complete EXACT mapping", err)
	}
}

func TestIncidentRejectsRootCauseConfirmationForInvalidHypothesis(t *testing.T) {
	now := time.Date(2026, 7, 12, 14, 30, 0, 0, time.UTC)
	incident := domain.NewIncident("incident-1", "workspace-1", now)
	hypothesis := domain.Hypothesis{
		ID: "hypothesis-1", WorkspaceID: "workspace-1", IncidentID: incident.ID,
		InvestigationID: "investigation-1", Status: domain.HypothesisProposed,
	}
	if err := incident.ConfirmRootCauseAt(&hypothesis, domain.Actor{Type: domain.ActorHuman, ID: "user-1"}, now); err == nil {
		t.Fatal("ConfirmRootCauseAt() error = nil, want invalid hypothesis rejection")
	}
	if incident.ConfirmedHypothesisID != "" || hypothesis.Status != domain.HypothesisProposed {
		t.Fatalf("invalid hypothesis changed confirmation state: %#v / %#v", incident, hypothesis)
	}
}

func TestIncidentValidateRejectsUnsafeOrOversizedResourceIDs(t *testing.T) {
	now := time.Date(2026, 7, 12, 16, 0, 0, 0, time.UTC)
	valid := domain.NewIncident("incident-1", "workspace-1", now)
	for name, mutate := range map[string]func(*domain.Incident){
		"id control":        func(value *domain.Incident) { value.ID = "incident\x00other" },
		"tenant oversized":  func(value *domain.Incident) { value.TenantID = strings.Repeat("t", domain.MaxResourceIDBytes+1) },
		"workspace control": func(value *domain.Incident) { value.WorkspaceID = "workspace\nother" },
		"service control":   func(value *domain.Incident) { value.ServiceID = "service\x00other" },
		"environment oversized": func(value *domain.Incident) {
			value.EnvironmentID = strings.Repeat("e", domain.MaxResourceIDBytes+1)
		},
		"confirmed hypothesis control": func(value *domain.Incident) { value.ConfirmedHypothesisID = "hypothesis\nother" },
	} {
		t.Run(name, func(t *testing.T) {
			item := valid
			mutate(&item)
			if err := item.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want resource ID rejection")
			}
		})
	}
}
