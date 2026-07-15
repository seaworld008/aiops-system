package assetdiscovery

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

const (
	testEnvironmentA = "11111111-1111-4111-8111-111111111111"
	testEnvironmentB = "22222222-2222-4222-8222-222222222222"
	testProviderKind = "CMDB_CATALOG_V1"
)

func TestFactPolicyCloneDeepCopiesEveryCollection(t *testing.T) {
	policy := validFactPolicy()
	clone := policy.Clone()

	clone.AuthorityEnvironmentIDs[0] = testEnvironmentB
	clone.TrustedPathCodes[0] = "CHANGED_PATH"
	clone.RelationshipTypes[0] = assetcatalog.RelationshipDependsOn
	clone.AllowedDocumentFields[assetcatalog.KindLinuxVM][0] = "changed_field"
	clone.AllowedDocumentFields[assetcatalog.KindWindowsVM] = []string{"name"}

	if policy.AuthorityEnvironmentIDs[0] != testEnvironmentA ||
		policy.TrustedPathCodes[0] != "CMDB_V1_DISPLAY_NAME" ||
		policy.RelationshipTypes[0] != assetcatalog.RelationshipContains ||
		policy.AllowedDocumentFields[assetcatalog.KindLinuxVM][0] != "cpu_count" {
		t.Fatalf("Clone mutated its source: %#v", policy)
	}
	if _, exists := policy.AllowedDocumentFields[assetcatalog.KindWindowsVM]; exists {
		t.Fatal("Clone shared its document-field map")
	}
}

func TestValidateFactsAcceptsCanonicalSourceOwnedFacts(t *testing.T) {
	if err := ValidateFacts(
		[]NormalizedItem{validNormalizedItem()},
		[]ObservedRelation{validObservedRelation()},
		validFactPolicy(),
	); err != nil {
		t.Fatalf("ValidateFacts() error = %v", err)
	}
}

func TestValidateFactsAcceptsExplicitEmptyAuthoritativeSnapshot(t *testing.T) {
	if err := ValidateFacts(nil, nil, validFactPolicy()); err != nil {
		t.Fatalf("ValidateFacts(empty) error = %v", err)
	}
}

func TestValidateFactsAcceptsCanonicalObjectTimeFreshnessAndTombstone(t *testing.T) {
	policy := validFactPolicy()
	policy.FreshnessKind = assetcatalog.FreshnessObjectTimeSequence
	observedAt := time.Date(2026, time.July, 15, 12, 30, 0, 123000, time.UTC)

	item := validNormalizedItem()
	item.Freshness.Kind = policy.FreshnessKind
	item.Freshness.OrderTime = &observedAt

	relation := validObservedRelation()
	relation.Freshness.Kind = policy.FreshnessKind
	relation.Freshness.OrderTime = &observedAt

	if err := ValidateFacts([]NormalizedItem{item}, []ObservedRelation{relation}, policy); err != nil {
		t.Fatalf("ValidateFacts(object time) error = %v", err)
	}

	tombstone := validTombstone()
	tombstone.Freshness.Kind = policy.FreshnessKind
	tombstone.Freshness.OrderTime = &observedAt
	if err := ValidateFacts([]NormalizedItem{tombstone}, nil, policy); err != nil {
		t.Fatalf("ValidateFacts(tombstone) error = %v", err)
	}
}

func TestValidateFactsRejectsEveryClosedContractGate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*[]NormalizedItem, *[]ObservedRelation, *FactPolicy)
	}{
		{
			name: "invalid policy provider",
			mutate: func(_ *[]NormalizedItem, _ *[]ObservedRelation, policy *FactPolicy) {
				policy.ProviderKind = "cmdb"
			},
		},
		{
			name: "unsorted policy authority",
			mutate: func(_ *[]NormalizedItem, _ *[]ObservedRelation, policy *FactPolicy) {
				policy.AuthorityEnvironmentIDs[0], policy.AuthorityEnvironmentIDs[1] =
					policy.AuthorityEnvironmentIDs[1], policy.AuthorityEnvironmentIDs[0]
			},
		},
		{
			name: "duplicate policy path",
			mutate: func(_ *[]NormalizedItem, _ *[]ObservedRelation, policy *FactPolicy) {
				policy.TrustedPathCodes = []string{"CMDB_V1_KIND", "CMDB_V1_KIND"}
			},
		},
		{
			name: "unsorted document fields",
			mutate: func(_ *[]NormalizedItem, _ *[]ObservedRelation, policy *FactPolicy) {
				policy.AllowedDocumentFields[assetcatalog.KindLinuxVM] = []string{"name", "cpu_count"}
			},
		},
		{
			name: "item count exceeds hard cap",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				*items = make([]NormalizedItem, maxFactItems+1)
			},
		},
		{
			name: "relation count exceeds hard cap",
			mutate: func(_ *[]NormalizedItem, relations *[]ObservedRelation, _ *FactPolicy) {
				*relations = make([]ObservedRelation, maxFactRelations+1)
			},
		},
		{
			name: "authority escape",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].EnvironmentID = "33333333-3333-4333-8333-333333333333"
			},
		},
		{
			name: "wrong provider",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].ProviderKind = "OTHER_PROVIDER_V1"
			},
		},
		{
			name: "unknown kind",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].Kind = assetcatalog.Kind("UNKNOWN")
			},
		},
		{
			name: "freshness kind drift",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].Freshness.Kind = assetcatalog.FreshnessCheckpointSequence
			},
		},
		{
			name: "freshness time on sequence profile",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				value := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
				(*items)[0].Freshness.OrderTime = &value
			},
		},
		{
			name: "freshness digest is noncanonical",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].Freshness.ProviderVersionSHA256 = strings.Repeat("A", 64)
			},
		},
		{
			name: "governance ownership in provider fact",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].FieldProvenance[0].Ownership = assetcatalog.FieldOwnershipGovernance
			},
		},
		{
			name: "missing required provenance",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].FieldProvenance = (*items)[0].FieldProvenance[:5]
			},
		},
		{
			name: "unknown provenance field",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].FieldProvenance[0].FieldCode = "credential"
			},
		},
		{
			name: "untrusted provenance path",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].FieldProvenance[0].ProviderPathCode = "UNTRUSTED_PATH"
			},
		},
		{
			name: "provenance confidence out of range",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].FieldProvenance[0].Confidence = 101
			},
		},
		{
			name: "noncanonical json",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				setDocument(&(*items)[0], `{"name":"vm-1","cpu_count":4}`)
			},
		},
		{
			name: "document hash mismatch",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].DocumentSHA256 = strings.Repeat("b", 64)
			},
		},
		{
			name: "unknown document field",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				setDocument(&(*items)[0], `{"cpu_count":4,"name":"vm-1","zone":"private"}`)
			},
		},
		{
			name: "oversized document",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				setDocument(&(*items)[0], `{"cpu_count":4,"name":"`+strings.Repeat("x", 64<<10)+`"}`)
			},
		},
		{
			name: "credential shaped document key",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, policy *FactPolicy) {
				policy.AllowedDocumentFields[assetcatalog.KindLinuxVM] = []string{"access_token", "cpu_count", "name"}
				setDocument(&(*items)[0], `{"access_token":"sensitive-canary","cpu_count":4,"name":"vm-1"}`)
			},
		},
		{
			name: "endpoint shaped document value",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				setDocument(&(*items)[0], `{"cpu_count":4,"name":"https://sensitive.example"}`)
			},
		},
		{
			name: "bare token shaped document value",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				setDocument(&(*items)[0], `{"cpu_count":4,"name":"sk-`+strings.Repeat("x", 24)+`"}`)
			},
		},
		{
			name: "credential shaped fingerprint",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].Fingerprints["private_key"] = "sensitive-canary"
			},
		},
		{
			name: "duplicate item identity",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				*items = append(*items, validNormalizedItem())
			},
		},
		{
			name: "tombstone carries document",
			mutate: func(items *[]NormalizedItem, _ *[]ObservedRelation, _ *FactPolicy) {
				(*items)[0].Tombstone = true
				(*items)[0].TombstoneReason = "SOURCE_DELETED"
			},
		},
		{
			name: "relation authority escape",
			mutate: func(_ *[]NormalizedItem, relations *[]ObservedRelation, _ *FactPolicy) {
				(*relations)[0].TargetEnvironmentID = "33333333-3333-4333-8333-333333333333"
			},
		},
		{
			name: "relation type outside profile",
			mutate: func(_ *[]NormalizedItem, relations *[]ObservedRelation, _ *FactPolicy) {
				(*relations)[0].Type = assetcatalog.RelationshipDependsOn
			},
		},
		{
			name: "relation path outside profile",
			mutate: func(_ *[]NormalizedItem, relations *[]ObservedRelation, _ *FactPolicy) {
				(*relations)[0].ProviderPathCode = "UNTRUSTED_RELATION"
			},
		},
		{
			name: "self relation",
			mutate: func(_ *[]NormalizedItem, relations *[]ObservedRelation, _ *FactPolicy) {
				(*relations)[0].TargetEnvironmentID = (*relations)[0].SourceEnvironmentID
				(*relations)[0].ToExternalID = (*relations)[0].FromExternalID
			},
		},
		{
			name: "duplicate relation identity",
			mutate: func(_ *[]NormalizedItem, relations *[]ObservedRelation, _ *FactPolicy) {
				*relations = append(*relations, validObservedRelation())
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			items := []NormalizedItem{validNormalizedItem()}
			relations := []ObservedRelation{validObservedRelation()}
			policy := validFactPolicy()
			test.mutate(&items, &relations, &policy)

			err := ValidateFacts(items, relations, policy)
			if !errors.Is(err, ErrFactContractViolation) {
				t.Fatalf("ValidateFacts() error = %v, want ErrFactContractViolation", err)
			}
			for _, secret := range []string{"sensitive-canary", "sensitive.example"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked rejected value: %v", err)
				}
			}
		})
	}
}

func TestValidateFactsRequiresSingleEnvironmentPolicyToBindEveryFact(t *testing.T) {
	policy := validFactPolicy()
	policy.EnvironmentMapping = assetcatalog.EnvironmentMappingSingle
	policy.AuthorityEnvironmentIDs = []string{testEnvironmentA}

	item := validNormalizedItem()
	relation := validObservedRelation()
	relation.TargetEnvironmentID = testEnvironmentA
	if err := ValidateFacts([]NormalizedItem{item}, []ObservedRelation{relation}, policy); err != nil {
		t.Fatalf("ValidateFacts(single environment) error = %v", err)
	}

	relation.TargetEnvironmentID = testEnvironmentB
	if err := ValidateFacts([]NormalizedItem{item}, []ObservedRelation{relation}, policy); !errors.Is(err, ErrFactContractViolation) {
		t.Fatalf("cross-environment single policy error = %v", err)
	}
}

func validFactPolicy() FactPolicy {
	return FactPolicy{
		ProviderKind:       testProviderKind,
		FreshnessKind:      assetcatalog.FreshnessObjectSequence,
		EnvironmentMapping: assetcatalog.EnvironmentMappingExplicitItem,
		AuthorityEnvironmentIDs: []string{
			testEnvironmentA,
			testEnvironmentB,
		},
		TrustedPathCodes: []string{
			"CMDB_V1_DISPLAY_NAME",
			"CMDB_V1_ENVIRONMENT_ID",
			"CMDB_V1_EXTERNAL_ID",
			"CMDB_V1_KIND",
			"CMDB_V1_PROVIDER_KIND",
			"CMDB_V1_RELATION",
			"CMDB_V1_TYPE_DETAILS",
		},
		RelationshipTypes: []assetcatalog.RelationshipType{assetcatalog.RelationshipContains},
		AllowedDocumentFields: map[assetcatalog.Kind][]string{
			assetcatalog.KindLinuxVM: {"cpu_count", "name"},
		},
	}
}

func validNormalizedItem() NormalizedItem {
	item := NormalizedItem{
		EnvironmentID: testEnvironmentA,
		ProviderKind:  testProviderKind,
		ExternalID:    "vm-1",
		Kind:          assetcatalog.KindLinuxVM,
		DisplayName:   "vm-1",
		SchemaVersion: "CMDB_V1",
		Freshness: FreshnessCandidate{
			Kind:                  assetcatalog.FreshnessObjectSequence,
			OrderSequence:         7,
			ProviderVersionSHA256: strings.Repeat("a", 64),
		},
		FieldProvenance: []FieldProvenance{
			{FieldCode: "display_name", ProviderPathCode: "CMDB_V1_DISPLAY_NAME", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
			{FieldCode: "environment_id", ProviderPathCode: "CMDB_V1_ENVIRONMENT_ID", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
			{FieldCode: "external_id", ProviderPathCode: "CMDB_V1_EXTERNAL_ID", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
			{FieldCode: "kind", ProviderPathCode: "CMDB_V1_KIND", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
			{FieldCode: "provider_kind", ProviderPathCode: "CMDB_V1_PROVIDER_KIND", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
			{FieldCode: "type_details", ProviderPathCode: "CMDB_V1_TYPE_DETAILS", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		},
		Fingerprints: map[string]string{"provider_instance_id": "vm-1"},
	}
	setDocument(&item, `{"cpu_count":4,"name":"vm-1"}`)
	return item
}

func validTombstone() NormalizedItem {
	return NormalizedItem{
		EnvironmentID:   testEnvironmentA,
		ProviderKind:    testProviderKind,
		ExternalID:      "vm-1",
		Tombstone:       true,
		TombstoneReason: "SOURCE_DELETED",
		Freshness: FreshnessCandidate{
			Kind:                  assetcatalog.FreshnessObjectSequence,
			OrderSequence:         8,
			ProviderVersionSHA256: strings.Repeat("b", 64),
		},
		FieldProvenance: []FieldProvenance{
			{FieldCode: "environment_id", ProviderPathCode: "CMDB_V1_ENVIRONMENT_ID", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
			{FieldCode: "external_id", ProviderPathCode: "CMDB_V1_EXTERNAL_ID", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
			{FieldCode: "provider_kind", ProviderPathCode: "CMDB_V1_PROVIDER_KIND", Ownership: assetcatalog.FieldOwnershipSource, Confidence: 100},
		},
	}
}

func validObservedRelation() ObservedRelation {
	return ObservedRelation{
		SourceEnvironmentID: testEnvironmentA,
		TargetEnvironmentID: testEnvironmentB,
		FromExternalID:      "vm-1",
		ToExternalID:        "vm-2",
		Type:                assetcatalog.RelationshipContains,
		ProviderPathCode:    "CMDB_V1_RELATION",
		Confidence:          100,
		Freshness: FreshnessCandidate{
			Kind:                  assetcatalog.FreshnessObjectSequence,
			OrderSequence:         9,
			ProviderVersionSHA256: strings.Repeat("c", 64),
		},
	}
}

func setDocument(item *NormalizedItem, document string) {
	item.Document = []byte(document)
	digest := sha256.Sum256(item.Document)
	item.DocumentSHA256 = hex.EncodeToString(digest[:])
}
