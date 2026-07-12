package domain_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
)

func TestInvestigationPlanBindingAndReadTaskRuntimeBindingValidateExactVersions(t *testing.T) {
	boundAt := time.Date(2026, 7, 12, 9, 30, 0, 123000, time.UTC)
	plan := validPlanBinding()
	runtime := validRuntimeBinding(boundAt)
	if err := plan.Validate(); err != nil {
		t.Fatalf("InvestigationPlanBinding.Validate() error = %v", err)
	}
	if err := runtime.Validate(); err != nil {
		t.Fatalf("ReadTaskRuntimeBinding.Validate() error = %v", err)
	}

	for name, mutate := range map[string]func(*domain.InvestigationPlanBinding){
		"schema":   func(value *domain.InvestigationPlanBinding) { value.SchemaVersion = "investigation-plan-manifest.v2" },
		"manifest": func(value *domain.InvestigationPlanBinding) { value.ManifestDigest = strings.Repeat("A", 64) },
		"registry": func(value *domain.InvestigationPlanBinding) { value.RegistryDigest = "" },
		"profile":  func(value *domain.InvestigationPlanBinding) { value.ProfileDigest = strings.Repeat("x", 64) },
		"tasks":    func(value *domain.InvestigationPlanBinding) { value.TasksHash = strings.Repeat("0", 63) },
	} {
		t.Run("plan "+name, func(t *testing.T) {
			candidate := plan
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want invalid plan binding")
			}
		})
	}

	for name, mutate := range map[string]func(*domain.ReadTaskRuntimeBinding){
		"schema":    func(value *domain.ReadTaskRuntimeBinding) { value.SchemaVersion = "read-task-runtime-binding.v2" },
		"connector": func(value *domain.ReadTaskRuntimeBinding) { value.ConnectorDigest = strings.Repeat("A", 64) },
		"target":    func(value *domain.ReadTaskRuntimeBinding) { value.TargetDigest = "" },
		"executor":  func(value *domain.ReadTaskRuntimeBinding) { value.ExecutorDigest = strings.Repeat("x", 64) },
		"runtime":   func(value *domain.ReadTaskRuntimeBinding) { value.RuntimeDigest = strings.Repeat("0", 63) },
		"zero time": func(value *domain.ReadTaskRuntimeBinding) { value.BoundAt = time.Time{} },
		"non UTC": func(value *domain.ReadTaskRuntimeBinding) {
			value.BoundAt = value.BoundAt.In(time.FixedZone("UTC+8", 8*60*60))
		},
		"sub-microsecond": func(value *domain.ReadTaskRuntimeBinding) { value.BoundAt = value.BoundAt.Add(time.Nanosecond) },
	} {
		t.Run("runtime "+name, func(t *testing.T) {
			candidate := runtime
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want invalid runtime binding")
			}
		})
	}
}

func TestConnectorDigestMatchesOnlyExactBoundedContentAddress(t *testing.T) {
	digest := strings.Repeat("5", 64)
	valid := "prometheus-prod-v1-" + digest
	if !domain.ConnectorDigestMatchesID(valid, digest) {
		t.Fatal("ConnectorDigestMatchesID() rejected an exact content-addressed connector")
	}
	for name, connectorID := range map[string]string{
		"legacy name":  "prometheus-prod",
		"wrong digest": "prometheus-prod-v1-" + strings.Repeat("6", 64),
		"empty prefix": "-v1-" + digest,
		"long prefix":  strings.Repeat("a", 61) + "-v1-" + digest,
		"upper digest": "prometheus-prod-v1-" + strings.Repeat("A", 64),
	} {
		t.Run(name, func(t *testing.T) {
			if domain.ConnectorDigestMatchesID(connectorID, digest) {
				t.Fatalf("ConnectorDigestMatchesID(%q) accepted mismatched identity", connectorID)
			}
		})
	}
}

func TestInvestigationValidationSeparatesLegacyV1FromBoundV2(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	base := domain.Investigation{
		ID: "investigation-1", WorkspaceID: "workspace-1", IncidentID: "incident-1",
		Status: domain.InvestigationQueued, ModelStatus: domain.ModelPending,
		IdempotencyKey: "investigate:binding", RequestHash: strings.Repeat("a", 64),
		CreatedAt: now, UpdatedAt: now,
	}
	legacy := base
	legacy.RequestHashVersion = domain.InvestigationCreateRequestVersionV1
	if err := legacy.Validate(); err != nil {
		t.Fatalf("legacy Investigation.Validate() error = %v", err)
	}
	bound := base
	bound.RequestHashVersion = domain.InvestigationCreateRequestVersionV2
	bound.PlanBinding = validPlanBinding()
	if err := bound.Validate(); err != nil {
		t.Fatalf("bound Investigation.Validate() error = %v", err)
	}

	for name, candidate := range map[string]domain.Investigation{
		"missing version": base,
		"v1 with binding": func() domain.Investigation { value := legacy; value.PlanBinding = validPlanBinding(); return value }(),
		"v2 without binding": func() domain.Investigation {
			value := bound
			value.PlanBinding = domain.InvestigationPlanBinding{}
			return value
		}(),
		"unknown version": func() domain.Investigation {
			value := legacy
			value.RequestHashVersion = "investigation.create.v3"
			return value
		}(),
		"partial v2 binding": func() domain.Investigation { value := bound; value.PlanBinding.TasksHash = ""; return value }(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := candidate.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want version/binding mismatch rejection")
			}
		})
	}
}

func TestReadTaskValidationAcceptsLegacyZeroBindingAndRequiresExactBoundAt(t *testing.T) {
	now := time.Date(2026, 7, 12, 11, 0, 0, 456000, time.UTC)
	input := json.RawMessage(`{"lookback_minutes":15}`)
	legacy := domain.ReadTask{
		ID: "task-1", WorkspaceID: "workspace-1", IncidentID: "incident-1", InvestigationID: "investigation-1",
		Key: "metrics", Position: 1, ConnectorID: "prometheus-prod", Operation: "range_query",
		Input: input, InputHash: sha256Hex(input), Status: domain.ReadTaskQueued, CreatedAt: now, UpdatedAt: now,
	}
	if err := legacy.Validate(); err != nil {
		t.Fatalf("legacy ReadTask.Validate() error = %v", err)
	}
	bound := legacy
	bound.RuntimeBinding = validRuntimeBinding(now)
	bound.ConnectorID = "prometheus-prod-v1-" + bound.RuntimeBinding.ConnectorDigest
	if err := bound.Validate(); err != nil {
		t.Fatalf("bound ReadTask.Validate() error = %v", err)
	}
	bound.RuntimeBinding.BoundAt = now.Add(time.Microsecond)
	bound.UpdatedAt = bound.RuntimeBinding.BoundAt
	if err := bound.Validate(); err == nil {
		t.Fatal("ReadTask accepted runtime BoundAt different from CreatedAt")
	}
	bound = legacy
	bound.RuntimeBinding = validRuntimeBinding(now)
	if err := bound.Validate(); err == nil {
		t.Fatal("ReadTask accepted a runtime digest unrelated to its ConnectorID")
	}
	bound = legacy
	bound.RuntimeBinding.SchemaVersion = domain.ReadTaskRuntimeBindingSchemaVersion
	if err := bound.Validate(); err == nil {
		t.Fatal("ReadTask accepted partial runtime binding")
	}
}

func validPlanBinding() domain.InvestigationPlanBinding {
	return domain.InvestigationPlanBinding{
		SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
		ManifestDigest: strings.Repeat("1", 64), RegistryDigest: strings.Repeat("2", 64),
		ProfileDigest: strings.Repeat("3", 64), TasksHash: strings.Repeat("4", 64),
	}
}

func validRuntimeBinding(boundAt time.Time) domain.ReadTaskRuntimeBinding {
	return domain.ReadTaskRuntimeBinding{
		SchemaVersion:   domain.ReadTaskRuntimeBindingSchemaVersion,
		ConnectorDigest: strings.Repeat("5", 64), TargetDigest: strings.Repeat("6", 64),
		ExecutorDigest: strings.Repeat("7", 64), RuntimeDigest: strings.Repeat("8", 64), BoundAt: boundAt,
	}
}
