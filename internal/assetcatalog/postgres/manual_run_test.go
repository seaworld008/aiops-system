package postgres

import (
	"bytes"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

func TestManualFramedDigestsUsePackOneGoldenEncoding(t *testing.T) {
	t.Parallel()

	if got, want := framedDigest(
		[]byte("manual-catalog-version.v1"),
		[]byte("10000000-0000-4000-8000-000000000201"),
		[]byte("20000000-0000-4000-8000-000000000201"),
		[]byte("60000000-0000-4000-8000-000000000201"),
		[]byte("1"),
		[]byte("1"),
	), "397cb2877e7bac712debd274eb530403db0cd637fe2e0e5b2dfdeb5f2aa622e9"; got != want {
		t.Fatalf("manual provider version digest = %s, want %s", got, want)
	}
	if got, want := framedDigest([]byte("asset-fingerprints.v1"), []byte("0")),
		"90e4de9011af97c92220d5ea0dd6cc97c764e262397b4a9970caeadadc37db79"; got != want {
		t.Fatalf("empty fingerprint digest = %s, want %s", got, want)
	}
	if got, want := framedDigest([]byte("asset-relation-page.v1"), []byte("0")),
		"b89ad607e709ef2ea85f7fc6eb0f80e32ae3ecf234220907a0fe718825f7c151"; got != want {
		t.Fatalf("empty relation page digest = %s, want %s", got, want)
	}
	if framedDigest(nil) == framedDigest([]byte{}) {
		t.Fatal("FramedTupleV1 must distinguish NULL from present-empty")
	}
}

func TestBuildManualFactsIsDeterministicCanonicalAndSemantic(t *testing.T) {
	t.Parallel()

	scope := assetcatalog.Scope{
		TenantID:      "10000000-0000-4000-8000-000000000201",
		WorkspaceID:   "20000000-0000-4000-8000-000000000201",
		EnvironmentID: "30000000-0000-4000-8000-000000000201",
	}
	manual := manualSourceState{
		source: assetcatalog.Source{
			ID: "60000000-0000-4000-8000-000000000201", ProviderKind: "MANUAL_V1",
		},
		revision: assetcatalog.SourceRevision{
			Revision:                1,
			CanonicalRevisionDigest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			SourceDefinitionDigest:  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		},
	}
	ids := manualRunIDs{
		observation: "63000000-0000-4000-8000-000000000201",
		run:         "62000000-0000-4000-8000-000000000201",
	}
	command := assetcatalog.CreateAssetCommand{
		SourceID: manual.source.ID, Kind: assetcatalog.KindLinuxVM,
		ExternalID: "host-<safe>", DisplayName: "Host <Safe>",
		Criticality:        assetcatalog.CriticalityHigh,
		DataClassification: assetcatalog.DataClassificationInternal,
		Labels:             map[string]string{},
	}
	when := time.Date(2026, 7, 15, 1, 2, 3, 456000000, time.UTC)
	first, err := buildManualFacts(scope, command, manual, ids, when, 1)
	if err != nil {
		t.Fatalf("buildManualFacts() error = %v", err)
	}
	second, err := buildManualFacts(scope, command, manual, ids, when, 1)
	if err != nil {
		t.Fatalf("buildManualFacts(second) error = %v", err)
	}
	if !bytes.Equal(first.document, second.document) || !bytes.Equal(first.provenance, second.provenance) ||
		first.providerFact != second.providerFact || first.chain != second.chain || first.page != second.page {
		t.Fatal("identical MANUAL facts were not deterministic")
	}
	if got, want := string(first.document), `{"display_name":"Host <Safe>","external_id":"host-<safe>","kind":"LINUX_VM"}`; got != want {
		t.Fatalf("canonical document = %s, want %s", got, want)
	}
	for name, value := range map[string][]byte{"document": first.document, "provenance": first.provenance} {
		canonical, err := jsoncanonicalizer.Transform(value)
		if err != nil || !bytes.Equal(canonical, value) {
			t.Fatalf("%s is not RFC 8785 canonical: %v", name, err)
		}
	}
	if first.providerVersion != "397cb2877e7bac712debd274eb530403db0cd637fe2e0e5b2dfdeb5f2aa622e9" {
		t.Fatalf("provider version = %s", first.providerVersion)
	}
	changed := command.Clone()
	changed.DisplayName = "Different"
	different, err := buildManualFacts(scope, changed, manual, ids, when, 1)
	if err != nil {
		t.Fatalf("buildManualFacts(changed) error = %v", err)
	}
	if different.providerVersion != first.providerVersion || different.providerFact == first.providerFact ||
		different.chain == first.chain || different.page == first.page {
		t.Fatal("MANUAL semantic digest inclusion/exclusion drifted")
	}
}

func TestManualRunFenceRejectsEveryCoordinateMismatchAndDestroy(t *testing.T) {
	t.Parallel()

	ids := []string{
		"70000000-0000-4000-8000-000000000001",
		"70000000-0000-4000-8000-000000000002",
		"70000000-0000-4000-8000-000000000003",
		"70000000-0000-4000-8000-000000000004",
		"70000000-0000-4000-8000-000000000005",
		"70000000-0000-4000-8000-000000000006",
		"70000000-0000-4000-8000-000000000007",
		"70000000-0000-4000-8000-000000000008",
		"70000000-0000-4000-8000-000000000009",
	}
	executor := newManualRunExecutor(ids)
	if err := executor.ensureFence(); err != nil {
		t.Fatalf("ensureFence() error = %v", err)
	}
	if !executor.fence.Matches(executor.ids.run, manualLeaseOwner, manualFenceEpoch, executor.fenceHash) {
		t.Fatal("fresh MANUAL fence did not match its exact persisted coordinates")
	}
	for name, matched := range map[string]bool{
		"run":   executor.fence.Matches(ids[0], manualLeaseOwner, manualFenceEpoch, executor.fenceHash),
		"owner": executor.fence.Matches(executor.ids.run, "other-owner", manualFenceEpoch, executor.fenceHash),
		"epoch": executor.fence.Matches(executor.ids.run, manualLeaseOwner, manualFenceEpoch+1, executor.fenceHash),
		"hash": executor.fence.Matches(
			executor.ids.run, manualLeaseOwner, manualFenceEpoch,
			"0000000000000000000000000000000000000000000000000000000000000000",
		),
	} {
		if matched {
			t.Errorf("MANUAL fence accepted mismatched %s", name)
		}
	}
	executor.destroy()
	if executor.fence.Matches(executor.ids.run, manualLeaseOwner, manualFenceEpoch, executor.fenceHash) {
		t.Fatal("destroyed MANUAL fence remained usable")
	}
}
