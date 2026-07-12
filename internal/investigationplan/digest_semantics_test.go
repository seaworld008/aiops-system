package investigationplan

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

type digestSnapshot struct {
	tasks       string
	profile     string
	manifest    string
	correlation string
}

func TestDigestDomainsBindExactlyTheirDeclaredSemantics(t *testing.T) {
	baseProfile := compiledProfile{
		registryDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		scope: investigation.TaskSpecScope{
			TenantID: "10000000-0000-4000-8000-000000000001", WorkspaceID: "20000000-0000-4000-8000-000000000002",
			EnvironmentID: "30000000-0000-4000-8000-000000000003", ServiceID: "40000000-0000-4000-8000-000000000004",
			MappingStatus: domain.MappingExact,
		},
		integrationID: "50000000-0000-4000-8000-000000000005",
		provider:      "alertmanager",
		labels: []LabelMatch{
			{Key: "cluster", Value: "staging-a"},
			{Key: "service", Value: "payments"},
		},
		tasks: []investigation.TaskSpec{{
			Key: "metrics", ConnectorID: "prometheus-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Operation: "range_query", Input: json.RawMessage(`{"lookback_minutes":15}`),
		}},
	}
	baseSignal := domain.Signal{
		IntegrationID: baseProfile.integrationID, Provider: baseProfile.provider,
		Fingerprint: "payments-staging-latency",
	}
	baseline := takeDigestSnapshot(t, baseProfile, baseSignal)
	tests := []struct {
		name                           string
		mutate                         func(*compiledProfile, *domain.Signal)
		tasks, profile, manifest, corr bool
	}{
		{name: "registry", mutate: func(profile *compiledProfile, _ *domain.Signal) {
			profile.registryDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}, profile: true, manifest: true},
		{name: "scope tenant", mutate: func(profile *compiledProfile, _ *domain.Signal) {
			profile.scope.TenantID = "10000000-0000-4000-8000-000000000011"
		}, profile: true, manifest: true, corr: true},
		{name: "scope workspace", mutate: func(profile *compiledProfile, _ *domain.Signal) {
			profile.scope.WorkspaceID = "20000000-0000-4000-8000-000000000012"
		}, profile: true, manifest: true, corr: true},
		{name: "scope environment", mutate: func(profile *compiledProfile, _ *domain.Signal) {
			profile.scope.EnvironmentID = "30000000-0000-4000-8000-000000000013"
		}, profile: true, manifest: true, corr: true},
		{name: "scope service", mutate: func(profile *compiledProfile, _ *domain.Signal) {
			profile.scope.ServiceID = "40000000-0000-4000-8000-000000000014"
		}, profile: true, manifest: true, corr: true},
		{name: "match integration", mutate: func(profile *compiledProfile, signal *domain.Signal) {
			profile.integrationID = "50000000-0000-4000-8000-000000000015"
			signal.IntegrationID = profile.integrationID
		}, profile: true, manifest: true, corr: true},
		{name: "match provider", mutate: func(profile *compiledProfile, signal *domain.Signal) {
			profile.provider = "grafana"
			signal.Provider = profile.provider
		}, profile: true, manifest: true, corr: true},
		{name: "first label key", mutate: func(profile *compiledProfile, _ *domain.Signal) { profile.labels[0].Key = "zone" }, profile: true, manifest: true},
		{name: "first label value", mutate: func(profile *compiledProfile, _ *domain.Signal) { profile.labels[0].Value = "staging-b" }, profile: true, manifest: true},
		{name: "second label key", mutate: func(profile *compiledProfile, _ *domain.Signal) { profile.labels[1].Key = "component" }, profile: true, manifest: true},
		{name: "second label value", mutate: func(profile *compiledProfile, _ *domain.Signal) { profile.labels[1].Value = "checkout" }, profile: true, manifest: true},
		{name: "task key", mutate: func(profile *compiledProfile, _ *domain.Signal) { profile.tasks[0].Key = "logs" }, tasks: true, profile: true, manifest: true},
		{name: "task connector", mutate: func(profile *compiledProfile, _ *domain.Signal) {
			profile.tasks[0].ConnectorID = "prometheus-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}, tasks: true, profile: true, manifest: true},
		{name: "task operation", mutate: func(profile *compiledProfile, _ *domain.Signal) { profile.tasks[0].Operation = "search" }, tasks: true, profile: true, manifest: true},
		{name: "task input", mutate: func(profile *compiledProfile, _ *domain.Signal) {
			profile.tasks[0].Input = json.RawMessage(`{"lookback_minutes":20}`)
		}, tasks: true, profile: true, manifest: true},
		{name: "fingerprint", mutate: func(_ *compiledProfile, signal *domain.Signal) { signal.Fingerprint = "payments-staging-errors" }, corr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := cloneCompiledProfile(baseProfile)
			signal := baseSignal
			test.mutate(&profile, &signal)
			got := takeDigestSnapshot(t, profile, signal)
			assertDigestChanged(t, "tasks", baseline.tasks, got.tasks, test.tasks)
			assertDigestChanged(t, "profile", baseline.profile, got.profile, test.profile)
			assertDigestChanged(t, "manifest", baseline.manifest, got.manifest, test.manifest)
			assertDigestChanged(t, "correlation", baseline.correlation, got.correlation, test.corr)
		})
	}
}

func takeDigestSnapshot(t *testing.T, profile compiledProfile, signal domain.Signal) digestSnapshot {
	t.Helper()
	sort.Slice(profile.labels, func(left, right int) bool {
		if profile.labels[left].Key != profile.labels[right].Key {
			return profile.labels[left].Key < profile.labels[right].Key
		}
		return profile.labels[left].Value < profile.labels[right].Value
	})
	canonical, tasksHash, err := investigation.CanonicalTaskSpecs(profile.tasks)
	if err != nil {
		t.Fatalf("CanonicalTaskSpecs() error = %v", err)
	}
	profile.tasks, profile.tasksHash = canonical, tasksHash
	profileDigest, err := digestProfile(profile)
	if err != nil {
		t.Fatalf("digestProfile() error = %v", err)
	}
	profile.profileDigest = profileDigest
	manifestDigest, err := digestManifest(profile.registryDigest, []compiledProfile{profile})
	if err != nil {
		t.Fatalf("digestManifest() error = %v", err)
	}
	correlation, err := correlationKey(profile, signal)
	if err != nil {
		t.Fatalf("correlationKey() error = %v", err)
	}
	return digestSnapshot{tasks: tasksHash, profile: profileDigest, manifest: manifestDigest, correlation: correlation}
}

func cloneCompiledProfile(source compiledProfile) compiledProfile {
	cloned := source
	cloned.labels = append([]LabelMatch(nil), source.labels...)
	cloned.tasks = cloneTaskSpecs(source.tasks)
	return cloned
}

func assertDigestChanged(t *testing.T, name, before, after string, want bool) {
	t.Helper()
	if changed := before != after; changed != want {
		t.Errorf("%s changed = %t, want %t (%q -> %q)", name, changed, want, before, after)
	}
}
