package memory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/investigation/memory"
	"github.com/seaworld008/aiops-system/internal/store"
)

func TestCorrelateFiringSignalCreatesOneIncidentAndReplayDoesNotRecount(t *testing.T) {
	now := time.Date(2026, 7, 11, 13, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	signal := testSignal("workspace-1", "signal-1", "firing", now)
	if created, err := repository.RegisterSignal(context.Background(), signal); err != nil || !created {
		t.Fatalf("RegisterSignal() = %v, %v; want true, nil", created, err)
	}
	request := investigation.CorrelateSignalRequest{
		WorkspaceID: "workspace-1", SignalID: "signal-1", CorrelationKey: "payments:prod:latency",
		ServiceID: "payments", EnvironmentID: "prod", MappingStatus: domain.MappingExact,
	}

	first, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(first) error = %v", err)
	}
	second, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(replay) error = %v", err)
	}
	if !first.Created || !first.Associated || !first.Counted {
		t.Fatalf("first result = %#v, want created/associated/counted", first)
	}
	if second.Created || !second.Associated || second.Counted || second.Incident.ID != first.Incident.ID {
		t.Fatalf("replay result = %#v, want same uncounted incident", second)
	}
	if second.Incident.SignalCount != 1 || second.Incident.LastSignalAt != now {
		t.Fatalf("incident signal metadata = %d/%s, want 1/%s", second.Incident.SignalCount, second.Incident.LastSignalAt, now)
	}
}

func TestGetSignalIsWorkspaceScopedAndReturnsDetachedLabels(t *testing.T) {
	now := time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	signal := testSignal("workspace-1", "signal-get", "firing", now)
	signal.Labels = map[string]string{"service": "payments"}
	if created, err := repository.RegisterSignal(context.Background(), signal); err != nil || !created {
		t.Fatalf("RegisterSignal() = %v, %v; want true, nil", created, err)
	}

	first, err := repository.GetSignal(context.Background(), signal.WorkspaceID, signal.ID)
	if err != nil {
		t.Fatalf("GetSignal() error = %v", err)
	}
	first.Labels["service"] = "mutated"
	second, err := repository.GetSignal(context.Background(), signal.WorkspaceID, signal.ID)
	if err != nil || second.Labels["service"] != "payments" {
		t.Fatalf("GetSignal(after caller mutation) = %#v, %v; want detached labels", second, err)
	}
	if _, err := repository.GetSignal(context.Background(), "workspace-2", signal.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetSignal(cross workspace) error = %v, want ErrNotFound", err)
	}
	if _, err := repository.GetSignal(context.Background(), "bad\x00workspace", signal.ID); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("GetSignal(invalid scope) error = %v, want ErrInvalidRequest", err)
	}
}

func TestCorrelateSignalKeepsExistingIncidentUpdatedAtMonotonic(t *testing.T) {
	base := time.Date(2026, 7, 13, 2, 0, 0, 0, time.UTC)
	clockNow := base.Add(10 * time.Minute)
	nextID := 0
	repository, err := memory.New(memory.Options{
		Clock: func() time.Time { return clockNow }, TenantResolver: testTenantResolver, TaskSpecAuthorizer: testTaskSpecAuthorizer,
		IDFactory: func() string { nextID++; return fmt.Sprintf("monotonic-correlation-%d", nextID) },
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	request := investigation.CorrelateSignalRequest{
		WorkspaceID: "workspace-1", CorrelationKey: "payments:prod:monotonic",
		ServiceID: "payments", EnvironmentID: "prod", MappingStatus: domain.MappingExact,
	}
	firstSignal := testSignal("workspace-1", "signal-monotonic-1", "firing", base)
	if _, err := repository.RegisterSignal(context.Background(), firstSignal); err != nil {
		t.Fatalf("RegisterSignal(first) error = %v", err)
	}
	request.SignalID = firstSignal.ID
	first, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(first) error = %v", err)
	}

	clockNow = base.Add(5 * time.Minute)
	secondSignal := testSignal("workspace-1", "signal-monotonic-2", "firing", base.Add(time.Minute))
	if _, err := repository.RegisterSignal(context.Background(), secondSignal); err != nil {
		t.Fatalf("RegisterSignal(second) error = %v", err)
	}
	request.SignalID = secondSignal.ID
	second, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(second) error = %v", err)
	}
	if second.Incident.UpdatedAt != first.Incident.UpdatedAt {
		t.Fatalf("UpdatedAt = %s, want monotonic previous %s", second.Incident.UpdatedAt, first.Incident.UpdatedAt)
	}
}

func TestCorrelateSignalRejectsActiveIncidentMappingMismatchWithoutPartialWrite(t *testing.T) {
	now := time.Date(2026, 7, 13, 2, 30, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*investigation.CorrelateSignalRequest){
		"mapping status": func(request *investigation.CorrelateSignalRequest) { request.MappingStatus = domain.MappingAmbiguous },
		"service":        func(request *investigation.CorrelateSignalRequest) { request.ServiceID = "checkout" },
		"environment":    func(request *investigation.CorrelateSignalRequest) { request.EnvironmentID = "staging" },
	} {
		t.Run(name, func(t *testing.T) {
			repository := newRepository(t, now)
			suffix := strings.ReplaceAll(name, " ", "-")
			firstSignal := testSignal("workspace-1", "signal-mapping-first-"+suffix, "firing", now)
			secondSignal := testSignal("workspace-1", "signal-mapping-second-"+suffix, "firing", now.Add(time.Minute))
			for _, signal := range []domain.Signal{firstSignal, secondSignal} {
				if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
					t.Fatalf("RegisterSignal(%s) error = %v", signal.ID, err)
				}
			}
			request := investigation.CorrelateSignalRequest{
				WorkspaceID: "workspace-1", SignalID: firstSignal.ID, CorrelationKey: "payments:prod:mapping-" + suffix,
				ServiceID: "payments", EnvironmentID: "prod", MappingStatus: domain.MappingExact,
			}
			first, err := repository.CorrelateSignal(context.Background(), request)
			if err != nil {
				t.Fatalf("CorrelateSignal(first) error = %v", err)
			}
			mismatched := request
			mismatched.SignalID = secondSignal.ID
			mutate(&mismatched)
			if _, err := repository.CorrelateSignal(context.Background(), mismatched); !errors.Is(err, store.ErrScopeViolation) {
				t.Fatalf("CorrelateSignal(mismatched %s) error = %v, want ErrScopeViolation", name, err)
			}
			stored, err := repository.GetIncident(context.Background(), "workspace-1", first.Incident.ID)
			if err != nil || stored != first.Incident {
				t.Fatalf("GetIncident(after mismatch) = %#v, %v; want unchanged %#v", stored, err, first.Incident)
			}
			corrected := request
			corrected.SignalID = secondSignal.ID
			accepted, err := repository.CorrelateSignal(context.Background(), corrected)
			if err != nil || accepted.Incident.SignalCount != 2 {
				t.Fatalf("CorrelateSignal(corrected) = %#v, %v; mismatch left partial association", accepted, err)
			}
		})
	}
}

func TestCorrelateSignalReplayRequiresOriginalRequestSemantics(t *testing.T) {
	now := time.Date(2026, 7, 12, 16, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	signal := testSignal("workspace-1", "signal-replay", "firing", now)
	if created, err := repository.RegisterSignal(context.Background(), signal); err != nil || !created {
		t.Fatalf("RegisterSignal() = %v, %v; want true, nil", created, err)
	}
	request := investigation.CorrelateSignalRequest{
		WorkspaceID: "workspace-1", SignalID: signal.ID, CorrelationKey: "key-a",
		ServiceID: "payments", EnvironmentID: "prod", MappingStatus: domain.MappingExact,
	}
	first, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(first) error = %v", err)
	}
	replay, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(exact replay) error = %v", err)
	}
	if replay.Incident.ID != first.Incident.ID || replay.Counted || !replay.Associated {
		t.Fatalf("CorrelateSignal(exact replay) = %#v, want same uncounted incident", replay)
	}

	for _, test := range []struct {
		name   string
		mutate func(*investigation.CorrelateSignalRequest)
	}{
		{name: "correlation key", mutate: func(value *investigation.CorrelateSignalRequest) { value.CorrelationKey = "key-b" }},
		{name: "mapping status", mutate: func(value *investigation.CorrelateSignalRequest) { value.MappingStatus = domain.MappingAmbiguous }},
		{name: "service ID", mutate: func(value *investigation.CorrelateSignalRequest) { value.ServiceID = "checkout" }},
		{name: "environment ID", mutate: func(value *investigation.CorrelateSignalRequest) { value.EnvironmentID = "staging" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := request
			test.mutate(&changed)
			if _, err := repository.CorrelateSignal(context.Background(), changed); !errors.Is(err, store.ErrIdempotencyConflict) {
				t.Fatalf("CorrelateSignal(changed replay) error = %v, want ErrIdempotencyConflict", err)
			}
		})
	}

	incident, err := repository.GetIncident(context.Background(), request.WorkspaceID, first.Incident.ID)
	if err != nil {
		t.Fatalf("GetIncident() error = %v", err)
	}
	if incident.SignalCount != 1 {
		t.Fatalf("SignalCount = %d, want unchanged count 1", incident.SignalCount)
	}
}

func TestResolvedSignalOnlyAssociatesAnExistingActiveIncidentOnce(t *testing.T) {
	now := time.Date(2026, 7, 11, 13, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	request := investigation.CorrelateSignalRequest{
		WorkspaceID: "workspace-1", CorrelationKey: "payments:prod:latency",
		ServiceID: "payments", EnvironmentID: "prod", MappingStatus: domain.MappingExact,
	}

	resolvedWithoutIncident := testSignal("workspace-1", "resolved-orphan", "resolved", now)
	if _, err := repository.RegisterSignal(context.Background(), resolvedWithoutIncident); err != nil {
		t.Fatalf("RegisterSignal(orphan) error = %v", err)
	}
	request.SignalID = resolvedWithoutIncident.ID
	orphan, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(orphan resolved) error = %v", err)
	}
	if orphan.Associated || orphan.Created || orphan.Counted || orphan.Incident.ID != "" {
		t.Fatalf("orphan resolved result = %#v, want no incident", orphan)
	}

	firing := testSignal("workspace-1", "firing-1", "firing", now)
	resolved := testSignal("workspace-1", "resolved-1", "resolved", now.Add(time.Minute))
	for _, item := range []domain.Signal{firing, resolved} {
		if _, err := repository.RegisterSignal(context.Background(), item); err != nil {
			t.Fatalf("RegisterSignal(%s) error = %v", item.ID, err)
		}
	}
	request.SignalID = firing.ID
	if _, err := repository.CorrelateSignal(context.Background(), request); err != nil {
		t.Fatalf("CorrelateSignal(firing) error = %v", err)
	}
	request.SignalID = resolved.ID
	first, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(resolved) error = %v", err)
	}
	replay, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(resolved replay) error = %v", err)
	}
	if !first.Associated || !first.Counted || first.Created || first.Incident.SignalCount != 2 {
		t.Fatalf("first resolved result = %#v, want one counted association", first)
	}
	if !replay.Associated || replay.Counted || replay.Incident.SignalCount != 2 {
		t.Fatalf("resolved replay result = %#v, want no recount", replay)
	}
}

func TestResolvedNoOpReplayRemainsStableAfterLaterFiringIncident(t *testing.T) {
	now := time.Date(2026, 7, 12, 19, 30, 0, 0, time.UTC)
	repository := newRepository(t, now)
	resolved := testSignal("workspace-1", "resolved-before-firing", "resolved", now)
	firing := testSignal("workspace-1", "firing-after-resolved", "firing", now.Add(time.Minute))
	for _, signal := range []domain.Signal{resolved, firing} {
		if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
			t.Fatalf("RegisterSignal(%s) error = %v", signal.ID, err)
		}
	}
	resolvedRequest := investigation.CorrelateSignalRequest{
		WorkspaceID: "workspace-1", SignalID: resolved.ID, CorrelationKey: "payments:prod:stable-noop", MappingStatus: domain.MappingUnresolved,
	}
	first, err := repository.CorrelateSignal(context.Background(), resolvedRequest)
	if err != nil || first.Associated || first.Counted || first.Incident.ID != "" {
		t.Fatalf("CorrelateSignal(first resolved) = %#v, %v; want no-op", first, err)
	}
	firingResult, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: "workspace-1", SignalID: firing.ID, CorrelationKey: resolvedRequest.CorrelationKey, MappingStatus: domain.MappingUnresolved,
	})
	if err != nil || !firingResult.Created || firingResult.Incident.SignalCount != 1 {
		t.Fatalf("CorrelateSignal(firing) = %#v, %v; want new single-signal incident", firingResult, err)
	}
	replay, err := repository.CorrelateSignal(context.Background(), resolvedRequest)
	if err != nil || replay.Associated || replay.Counted || replay.Incident.ID != "" {
		t.Fatalf("CorrelateSignal(resolved replay) = %#v, %v; want stable no-op", replay, err)
	}
	incident, err := repository.GetIncident(context.Background(), "workspace-1", firingResult.Incident.ID)
	if err != nil || incident.SignalCount != 1 {
		t.Fatalf("GetIncident() = %#v, %v; want unchanged signal count", incident, err)
	}
	changed := resolvedRequest
	changed.CorrelationKey = "payments:prod:changed-noop"
	if _, err := repository.CorrelateSignal(context.Background(), changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("CorrelateSignal(changed no-op replay) error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestIncidentCorrelationAndReadsAreWorkspaceIsolated(t *testing.T) {
	now := time.Date(2026, 7, 11, 13, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	var incidentIDs []string
	for _, workspaceID := range []string{"workspace-1", "workspace-2"} {
		signal := testSignal(workspaceID, "shared-signal-id", "firing", now)
		if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
			t.Fatalf("RegisterSignal(%s) error = %v", workspaceID, err)
		}
		result, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
			WorkspaceID: workspaceID, SignalID: signal.ID, CorrelationKey: "payments:prod:latency",
			MappingStatus: domain.MappingUnresolved,
		})
		if err != nil {
			t.Fatalf("CorrelateSignal(%s) error = %v", workspaceID, err)
		}
		incidentIDs = append(incidentIDs, result.Incident.ID)
		items, err := repository.ListIncidents(context.Background(), investigation.ListIncidentsRequest{WorkspaceID: workspaceID})
		if err != nil || len(items) != 1 || items[0].WorkspaceID != workspaceID {
			t.Fatalf("ListIncidents(%s) = %#v, %v; want one scoped item", workspaceID, items, err)
		}
	}
	if incidentIDs[0] == incidentIDs[1] {
		t.Fatalf("incident IDs = %v, want independent incidents", incidentIDs)
	}
	if _, err := repository.GetIncident(context.Background(), "workspace-2", incidentIDs[0]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetIncident(cross-workspace) error = %v, want ErrNotFound", err)
	}
}

func TestCorrelateSignalUsesTrustedTenantResolverWithoutPartialWrites(t *testing.T) {
	now := time.Date(2026, 7, 12, 19, 15, 0, 0, time.UTC)
	resolverFails := true
	repository, err := memory.New(memory.Options{
		Clock:              func() time.Time { return now },
		IDFactory:          func() string { return "incident-tenant" },
		TaskSpecAuthorizer: testTaskSpecAuthorizer,
		TenantResolver: func(workspaceID string) (string, error) {
			if resolverFails {
				return "", errors.New("tenant resolver unavailable")
			}
			return "tenant-1", nil
		},
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	signal := testSignal("workspace-1", "signal-tenant", "firing", now)
	if _, err := repository.RegisterSignal(context.Background(), signal); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("RegisterSignal(resolver failure) error = %v, want ErrInvalidRequest", err)
	}
	request := investigation.CorrelateSignalRequest{
		WorkspaceID: signal.WorkspaceID, SignalID: signal.ID, CorrelationKey: "tenant:test", MappingStatus: domain.MappingUnresolved,
	}
	if _, err := repository.CorrelateSignal(context.Background(), request); !errors.Is(err, store.ErrScopeViolation) {
		t.Fatalf("CorrelateSignal(unregistered snapshot) error = %v, want ErrScopeViolation", err)
	}
	incidents, err := repository.ListIncidents(context.Background(), investigation.ListIncidentsRequest{WorkspaceID: signal.WorkspaceID})
	if err != nil || len(incidents) != 0 {
		t.Fatalf("ListIncidents() = %#v, %v; want no partial incident", incidents, err)
	}

	resolverFails = false
	if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal(resolver recovery) error = %v", err)
	}
	result, err := repository.CorrelateSignal(context.Background(), request)
	if err != nil {
		t.Fatalf("CorrelateSignal(resolver recovery) error = %v", err)
	}
	if result.Incident.TenantID != "tenant-1" || result.Incident.WorkspaceID != signal.WorkspaceID {
		t.Fatalf("tenant/workspace = %q/%q, want trusted distinct scope", result.Incident.TenantID, result.Incident.WorkspaceID)
	}
}

func TestNewRepositoryRequiresTrustedTenantResolver(t *testing.T) {
	now := time.Date(2026, 7, 12, 19, 20, 0, 0, time.UTC)
	if _, err := memory.New(memory.Options{
		Clock: func() time.Time { return now }, IDFactory: func() string { return "generated-1" },
		TaskSpecAuthorizer: testTaskSpecAuthorizer,
	}); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("memory.New(without TenantResolver) error = %v, want ErrInvalidRequest", err)
	}
}

func TestNewRepositoryRequiresTrustedTaskSpecAuthorizer(t *testing.T) {
	_, err := memory.New(memory.Options{
		Clock:          func() time.Time { return time.Date(2026, 7, 13, 4, 30, 0, 0, time.UTC) },
		IDFactory:      func() string { return "generated-1" },
		TenantResolver: testTenantResolver,
	})
	if !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("memory.New(without TaskSpecAuthorizer) error = %v, want ErrInvalidRequest", err)
	}
}

func TestConcurrentSignalStormMergesIntoOneIncidentWithExactTimeBounds(t *testing.T) {
	now := time.Date(2026, 7, 11, 19, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	const goroutines = 64
	for index := 0; index < goroutines; index++ {
		signal := testSignal("workspace-1", fmt.Sprintf("storm-%02d", index), "firing", now.Add(time.Duration(index-(goroutines-1))*time.Minute))
		if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
			t.Fatalf("RegisterSignal(%d) error = %v", index, err)
		}
	}
	start := make(chan struct{})
	results := make(chan investigation.CorrelateSignalResult, goroutines)
	errorsCh := make(chan error, goroutines)
	var group sync.WaitGroup
	for index := 0; index < goroutines; index++ {
		index := index
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			result, err := repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
				WorkspaceID: "workspace-1", SignalID: fmt.Sprintf("storm-%02d", index),
				CorrelationKey: "payments:prod:storm", MappingStatus: domain.MappingUnresolved,
			})
			results <- result
			errorsCh <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("CorrelateSignal() error = %v", err)
		}
	}
	created := 0
	var incidentID string
	for result := range results {
		if result.Created {
			created++
		}
		if incidentID == "" {
			incidentID = result.Incident.ID
		} else if result.Incident.ID != incidentID {
			t.Fatalf("incident ID = %q, want %q", result.Incident.ID, incidentID)
		}
	}
	stored, err := repository.GetIncident(context.Background(), "workspace-1", incidentID)
	if err != nil {
		t.Fatalf("GetIncident() error = %v", err)
	}
	if created != 1 || stored.SignalCount != goroutines || stored.OpenedAt != now.Add(-(goroutines-1)*time.Minute) ||
		stored.LastSignalAt != now {
		t.Fatalf("storm result created=%d incident=%#v", created, stored)
	}
}

func TestRegisterSignalCopiesCallerLabels(t *testing.T) {
	now := time.Date(2026, 7, 11, 20, 30, 0, 0, time.UTC)
	repository := newRepository(t, now)
	signal := testSignal("workspace-1", "signal-labels", "firing", now)
	if _, err := repository.RegisterSignal(context.Background(), signal); err != nil {
		t.Fatalf("RegisterSignal(first) error = %v", err)
	}
	signal.Labels["service"] = "tampered"
	replay := testSignal("workspace-1", "signal-labels", "firing", now)
	created, err := repository.RegisterSignal(context.Background(), replay)
	if err != nil || created {
		t.Fatalf("RegisterSignal(replay) = %v, %v; want false, nil after caller mutation", created, err)
	}
}

func TestRegisterSignalNormalizesEquivalentObservedAtInstantsForReplay(t *testing.T) {
	now := time.Date(2026, 7, 13, 6, 0, 0, 0, time.UTC)
	repository := newRepository(t, now)
	first := testSignal("workspace-1", "signal-timezone-replay", "firing", now.In(time.FixedZone("UTC+8", 8*60*60)))
	if created, err := repository.RegisterSignal(context.Background(), first); err != nil || !created {
		t.Fatalf("RegisterSignal(first) = %v, %v; want created", created, err)
	}
	replay := testSignal("workspace-1", "signal-timezone-replay", "firing", now)
	if created, err := repository.RegisterSignal(context.Background(), replay); err != nil || created {
		t.Fatalf("RegisterSignal(equivalent instant replay) = %v, %v; want false, nil", created, err)
	}
}

func TestRegisterSignalReplaySurvivesClockRollbackBeyondFutureSkew(t *testing.T) {
	base := time.Date(2026, 7, 13, 6, 5, 0, 0, time.UTC)
	clockNow := base
	nextID := 0
	repository, err := memory.New(memory.Options{
		Clock: func() time.Time { return clockNow }, TenantResolver: testTenantResolver, TaskSpecAuthorizer: testTaskSpecAuthorizer,
		IDFactory: func() string { nextID++; return fmt.Sprintf("signal-clock-replay-%d", nextID) },
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	accepted := testSignal("workspace-1", "signal-clock-replay", "firing", base.Add(4*time.Minute))
	accepted.Labels = nil
	if created, err := repository.RegisterSignal(context.Background(), accepted); err != nil || !created {
		t.Fatalf("RegisterSignal(first) = %v, %v; want accepted", created, err)
	}
	clockNow = base.Add(-time.Hour)
	replay := accepted
	replay.Labels = map[string]string{}
	if created, err := repository.RegisterSignal(context.Background(), replay); err != nil || created {
		t.Fatalf("RegisterSignal(replay after rollback) = %v, %v; want existing fact", created, err)
	}
	newSignal := replay
	newSignal.ID = "signal-clock-new"
	newSignal.ProviderEventID = newSignal.ID
	newSignal.PayloadHash = sha256Hex([]byte("payload-" + newSignal.ID))
	if _, err := repository.RegisterSignal(context.Background(), newSignal); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("RegisterSignal(new future fact after rollback) error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegisterSignalEnforcesTrustedFutureSkewWithoutPartialWrite(t *testing.T) {
	now := time.Date(2026, 7, 13, 6, 15, 0, 0, time.UTC)
	repository := newRepository(t, now)
	boundary := testSignal("workspace-1", "signal-future-boundary", "firing", now.Add(investigation.MaxSignalFutureSkew))
	if created, err := repository.RegisterSignal(context.Background(), boundary); err != nil || !created {
		t.Fatalf("RegisterSignal(boundary) = %v, %v; want accepted", created, err)
	}
	tooFuture := testSignal("workspace-1", "signal-too-future", "firing", now.Add(investigation.MaxSignalFutureSkew+time.Nanosecond))
	if _, err := repository.RegisterSignal(context.Background(), tooFuture); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("RegisterSignal(too future) error = %v, want ErrInvalidRequest", err)
	}
	corrected := testSignal("workspace-1", tooFuture.ID, "firing", now)
	if created, err := repository.RegisterSignal(context.Background(), corrected); err != nil || !created {
		t.Fatalf("RegisterSignal(corrected) = %v, %v; future rejection left partial write", created, err)
	}
}

func TestRegisterSignalEnforcesInvestigationFixtureBoundary(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	valid := testSignal("workspace-1", "signal-boundary", "firing", now)

	tooManyLabels := make(map[string]string, 65)
	for index := 0; index < 65; index++ {
		tooManyLabels[fmt.Sprintf("label_%02d", index)] = "value"
	}
	for name, mutate := range map[string]func(*domain.Signal){
		"short payload hash": func(signal *domain.Signal) { signal.PayloadHash = "short" },
		"uppercase payload hash": func(signal *domain.Signal) {
			signal.PayloadHash = strings.Repeat("A", 64)
		},
		"too many labels": func(signal *domain.Signal) { signal.Labels = tooManyLabels },
		"unsafe label key": func(signal *domain.Signal) {
			signal.Labels = map[string]string{"bad\nkey": "value"}
		},
		"unsafe label value": func(signal *domain.Signal) {
			signal.Labels = map[string]string{"service": "payments\x00other"}
		},
		"sensitive label": func(signal *domain.Signal) {
			signal.Labels = map[string]string{"authorization": "Bearer fixture-canary"}
		},
		"oversized signal id": func(signal *domain.Signal) {
			signal.ID = strings.Repeat("s", domain.MaxResourceIDBytes+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := newRepository(t, now)
			item := valid
			item.Labels = cloneStringMap(valid.Labels)
			mutate(&item)
			if _, err := repository.RegisterSignal(context.Background(), item); !errors.Is(err, investigation.ErrInvalidRequest) {
				t.Fatalf("RegisterSignal() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestCorrelateSignalValidatesOptionalAndExactMappingResourceIDs(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 30, 0, 0, time.UTC)
	for name, request := range map[string]investigation.CorrelateSignalRequest{
		"exact unsafe service": {
			WorkspaceID: "workspace-1", SignalID: "signal-1", CorrelationKey: "payments:prod:exact",
			MappingStatus: domain.MappingExact, ServiceID: "payments\x00other", EnvironmentID: "prod",
		},
		"ambiguous unsafe optional service": {
			WorkspaceID: "workspace-1", SignalID: "signal-1", CorrelationKey: "payments:prod:ambiguous",
			MappingStatus: domain.MappingAmbiguous, ServiceID: "payments\nother",
		},
		"unresolved oversized optional environment": {
			WorkspaceID: "workspace-1", SignalID: "signal-1", CorrelationKey: "payments:prod:unresolved",
			MappingStatus: domain.MappingUnresolved, EnvironmentID: strings.Repeat("e", domain.MaxResourceIDBytes+1),
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := newRepository(t, now)
			if _, err := repository.RegisterSignal(context.Background(), testSignal("workspace-1", "signal-1", "firing", now)); err != nil {
				t.Fatalf("RegisterSignal() error = %v", err)
			}
			if _, err := repository.CorrelateSignal(context.Background(), request); !errors.Is(err, investigation.ErrInvalidRequest) {
				t.Fatalf("CorrelateSignal() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestCorrelateSignalRejectsDuplicateGeneratedIncidentIDWithoutPartialWrites(t *testing.T) {
	now := time.Date(2026, 7, 12, 15, 0, 0, 0, time.UTC)
	repository, err := memory.New(memory.Options{
		Clock: func() time.Time { return now }, IDFactory: func() string { return "duplicate-incident" }, TenantResolver: testTenantResolver,
		TaskSpecAuthorizer: testTaskSpecAuthorizer,
	})
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	for _, id := range []string{"signal-first", "signal-second"} {
		if _, err := repository.RegisterSignal(context.Background(), testSignal("workspace-1", id, "firing", now)); err != nil {
			t.Fatalf("RegisterSignal(%s) error = %v", id, err)
		}
	}
	firstRequest := investigation.CorrelateSignalRequest{WorkspaceID: "workspace-1", SignalID: "signal-first", CorrelationKey: "first:key", MappingStatus: domain.MappingUnresolved}
	first, err := repository.CorrelateSignal(context.Background(), firstRequest)
	if err != nil {
		t.Fatalf("CorrelateSignal(first) error = %v", err)
	}
	_, err = repository.CorrelateSignal(context.Background(), investigation.CorrelateSignalRequest{
		WorkspaceID: "workspace-1", SignalID: "signal-second", CorrelationKey: "second:key", MappingStatus: domain.MappingUnresolved,
	})
	if !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CorrelateSignal(duplicate ID) error = %v, want ErrInvalidRequest", err)
	}
	items, err := repository.ListIncidents(context.Background(), investigation.ListIncidentsRequest{WorkspaceID: "workspace-1"})
	if err != nil || len(items) != 1 || items[0].ID != first.Incident.ID || items[0].CorrelationKey != "first:key" || items[0].SignalCount != 1 {
		t.Fatalf("ListIncidents() = %#v, %v; want unchanged first incident", items, err)
	}
	replay, err := repository.CorrelateSignal(context.Background(), firstRequest)
	if err != nil || replay.Incident.SignalCount != 1 {
		t.Fatalf("CorrelateSignal(first replay) = %#v, %v; want unchanged count", replay, err)
	}
}
