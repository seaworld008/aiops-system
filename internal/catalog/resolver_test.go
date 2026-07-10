package catalog_test

import (
	"reflect"
	"testing"

	"github.com/seaworld008/aiops-system/internal/catalog"
)

func TestResolveReturnsExactForOneExplicitServiceMatch(t *testing.T) {
	resolver := catalog.NewResolver([]catalog.ServiceBinding{
		{
			ID:            "binding-checkout",
			WorkspaceID:   "workspace-1",
			EnvironmentID: "production",
			ServiceID:     "checkout-api",
			MatchLabels: map[string]string{
				"service": "checkout",
				"cluster": "prod-a",
			},
		},
	})

	result := resolver.Resolve(catalog.ResolveInput{
		WorkspaceID:   "workspace-1",
		EnvironmentID: "production",
		AlertLabels: map[string]string{
			"service":  "checkout",
			"cluster":  "prod-a",
			"severity": "critical",
		},
	})

	if result.Status != catalog.MappingExact {
		t.Fatalf("Status = %q, want %q", result.Status, catalog.MappingExact)
	}
	if want := []string{"checkout-api"}; !reflect.DeepEqual(result.CandidateServiceIDs, want) {
		t.Fatalf("CandidateServiceIDs = %#v, want %#v", result.CandidateServiceIDs, want)
	}
	if result.Reason != catalog.ReasonUniqueExplicitMatch {
		t.Fatalf("Reason = %q, want %q", result.Reason, catalog.ReasonUniqueExplicitMatch)
	}
}

func TestResolveReturnsAmbiguousWithDeterministicCandidates(t *testing.T) {
	resolver := catalog.NewResolver([]catalog.ServiceBinding{
		{
			ID:            "binding-orders",
			WorkspaceID:   "workspace-1",
			EnvironmentID: "production",
			ServiceID:     "orders-api",
			MatchLabels:   map[string]string{"team": "commerce"},
		},
		{
			ID:            "binding-checkout",
			WorkspaceID:   "workspace-1",
			EnvironmentID: "production",
			ServiceID:     "checkout-api",
			MatchLabels:   map[string]string{"team": "commerce"},
		},
	})

	result := resolver.Resolve(catalog.ResolveInput{
		WorkspaceID:   "workspace-1",
		EnvironmentID: "production",
		AlertLabels:   map[string]string{"team": "commerce"},
	})

	if result.Status != catalog.MappingAmbiguous {
		t.Fatalf("Status = %q, want %q", result.Status, catalog.MappingAmbiguous)
	}
	if want := []string{"checkout-api", "orders-api"}; !reflect.DeepEqual(result.CandidateServiceIDs, want) {
		t.Fatalf("CandidateServiceIDs = %#v, want %#v", result.CandidateServiceIDs, want)
	}
	if result.Reason != catalog.ReasonMultipleExplicitMatches {
		t.Fatalf("Reason = %q, want %q", result.Reason, catalog.ReasonMultipleExplicitMatches)
	}
}

func TestResolveRequiresExactlyOneMatchingBindingForExact(t *testing.T) {
	resolver := catalog.NewResolver([]catalog.ServiceBinding{
		{
			ID:            "binding-checkout-by-service",
			WorkspaceID:   "workspace-1",
			EnvironmentID: "production",
			ServiceID:     "checkout-api",
			MatchLabels:   map[string]string{"service": "checkout"},
		},
		{
			ID:            "binding-checkout-by-team",
			WorkspaceID:   "workspace-1",
			EnvironmentID: "production",
			ServiceID:     "checkout-api",
			MatchLabels:   map[string]string{"team": "commerce"},
		},
	})

	result := resolver.Resolve(catalog.ResolveInput{
		WorkspaceID:   "workspace-1",
		EnvironmentID: "production",
		AlertLabels: map[string]string{
			"service": "checkout",
			"team":    "commerce",
		},
	})

	if result.Status != catalog.MappingAmbiguous {
		t.Fatalf("Status = %q, want %q", result.Status, catalog.MappingAmbiguous)
	}
	if want := []string{"checkout-api"}; !reflect.DeepEqual(result.CandidateServiceIDs, want) {
		t.Fatalf("CandidateServiceIDs = %#v, want %#v", result.CandidateServiceIDs, want)
	}
	if result.Reason != catalog.ReasonMultipleExplicitMatches {
		t.Fatalf("Reason = %q, want %q", result.Reason, catalog.ReasonMultipleExplicitMatches)
	}
}

func TestResolveReturnsUnresolvedWhenNoExplicitBindingMatches(t *testing.T) {
	resolver := catalog.NewResolver([]catalog.ServiceBinding{
		{
			ID:            "binding-payments",
			WorkspaceID:   "workspace-1",
			EnvironmentID: "production",
			ServiceID:     "payments-api",
			MatchLabels:   map[string]string{"service": "payments-api"},
		},
	})

	result := resolver.Resolve(catalog.ResolveInput{
		WorkspaceID:   "workspace-1",
		EnvironmentID: "production",
		AlertLabels:   map[string]string{"service": "payments"},
	})

	if result.Status != catalog.MappingUnresolved {
		t.Fatalf("Status = %q, want %q", result.Status, catalog.MappingUnresolved)
	}
	if len(result.CandidateServiceIDs) != 0 {
		t.Fatalf("CandidateServiceIDs = %#v, want empty", result.CandidateServiceIDs)
	}
	if result.Reason != catalog.ReasonNoExplicitMatch {
		t.Fatalf("Reason = %q, want %q", result.Reason, catalog.ReasonNoExplicitMatch)
	}
}

func TestResolveScopesBindingsByWorkspaceAndEnvironment(t *testing.T) {
	resolver := catalog.NewResolver([]catalog.ServiceBinding{
		{
			ID:            "binding-correct-scope",
			WorkspaceID:   "workspace-1",
			EnvironmentID: "production",
			ServiceID:     "production-api",
			MatchLabels:   map[string]string{"service": "shared-name"},
		},
		{
			ID:            "binding-other-workspace",
			WorkspaceID:   "workspace-2",
			EnvironmentID: "production",
			ServiceID:     "other-workspace-api",
			MatchLabels:   map[string]string{"service": "shared-name"},
		},
		{
			ID:            "binding-other-environment",
			WorkspaceID:   "workspace-1",
			EnvironmentID: "staging",
			ServiceID:     "staging-api",
			MatchLabels:   map[string]string{"service": "shared-name"},
		},
	})

	result := resolver.Resolve(catalog.ResolveInput{
		WorkspaceID:   "workspace-1",
		EnvironmentID: "production",
		AlertLabels:   map[string]string{"service": "shared-name"},
	})

	if result.Status != catalog.MappingExact {
		t.Fatalf("Status = %q, want %q", result.Status, catalog.MappingExact)
	}
	if want := []string{"production-api"}; !reflect.DeepEqual(result.CandidateServiceIDs, want) {
		t.Fatalf("CandidateServiceIDs = %#v, want %#v", result.CandidateServiceIDs, want)
	}
}

func TestResolveDoesNotTreatEmptyBindingAsWildcard(t *testing.T) {
	resolver := catalog.NewResolver([]catalog.ServiceBinding{
		{
			ID:            "binding-without-label-rule",
			WorkspaceID:   "workspace-1",
			EnvironmentID: "production",
			ServiceID:     "catch-all-service",
			MatchLabels:   map[string]string{},
		},
	})

	result := resolver.Resolve(catalog.ResolveInput{
		WorkspaceID:   "workspace-1",
		EnvironmentID: "production",
		AlertLabels:   map[string]string{"service": "anything"},
	})

	if result.Status != catalog.MappingUnresolved {
		t.Fatalf("Status = %q, want %q", result.Status, catalog.MappingUnresolved)
	}
	if len(result.CandidateServiceIDs) != 0 {
		t.Fatalf("CandidateServiceIDs = %#v, want empty", result.CandidateServiceIDs)
	}
}

func TestResolveRejectsMissingScope(t *testing.T) {
	resolver := catalog.NewResolver([]catalog.ServiceBinding{{
		ID:            "binding-empty-workspace",
		EnvironmentID: "production",
		ServiceID:     "unsafe-match",
		MatchLabels:   map[string]string{"service": "api"},
	}})

	result := resolver.Resolve(catalog.ResolveInput{
		EnvironmentID: "production",
		AlertLabels:   map[string]string{"service": "api"},
	})
	if result.Status != catalog.MappingUnresolved {
		t.Fatalf("Status = %q, want %q", result.Status, catalog.MappingUnresolved)
	}
}

func TestResolverSnapshotsBindingRules(t *testing.T) {
	bindings := []catalog.ServiceBinding{{
		ID:            "binding-api",
		WorkspaceID:   "workspace-1",
		EnvironmentID: "production",
		ServiceID:     "api",
		MatchLabels:   map[string]string{"service": "api"},
	}}
	resolver := catalog.NewResolver(bindings)
	bindings[0].MatchLabels["service"] = "tampered"

	result := resolver.Resolve(catalog.ResolveInput{
		WorkspaceID:   "workspace-1",
		EnvironmentID: "production",
		AlertLabels:   map[string]string{"service": "api"},
	})
	if result.Status != catalog.MappingExact {
		t.Fatalf("Status after caller mutation = %q, want %q", result.Status, catalog.MappingExact)
	}
}
