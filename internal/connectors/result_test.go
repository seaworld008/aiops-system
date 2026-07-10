package connectors

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestValidateResultBindsHashToFinalItems(t *testing.T) {
	t.Parallel()

	items := []json.RawMessage{json.RawMessage(`{"status":"healthy"}`)}
	hash, err := HashItems(items)
	if err != nil {
		t.Fatalf("HashItems() error = %v", err)
	}
	result := Result{
		Source: "test", Query: "safe-query", CollectedAt: time.Now().UTC(),
		ItemCount: len(items), ContentHash: hash, Items: items,
	}
	if err := ValidateResult(result); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}

	result.Items[0] = json.RawMessage(`{"status":"tampered"}`)
	if err := ValidateResult(result); err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("tampered result error = %v, want hash mismatch", err)
	}
}

func TestValidateResultRejectsMalformedContract(t *testing.T) {
	t.Parallel()

	validItems := []json.RawMessage{json.RawMessage(`{"ok":true}`)}
	hash, err := HashItems(validItems)
	if err != nil {
		t.Fatalf("HashItems() error = %v", err)
	}
	base := Result{Source: "test", Query: "query", CollectedAt: time.Now().UTC(), ItemCount: 1, ContentHash: hash, Items: validItems}
	tests := map[string]func(*Result){
		"missing source":  func(result *Result) { result.Source = "" },
		"missing time":    func(result *Result) { result.CollectedAt = time.Time{} },
		"item count":      func(result *Result) { result.ItemCount = 2 },
		"invalid JSON":    func(result *Result) { result.Items = []json.RawMessage{json.RawMessage(`{`)} },
		"oversized query": func(result *Result) { result.Query = strings.Repeat("q", MaxEvidenceQueryBytes+1) },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Items = append([]json.RawMessage(nil), base.Items...)
			mutate(&candidate)
			if err := ValidateResult(candidate); err == nil {
				t.Fatal("malformed result was accepted")
			}
		})
	}
}

func TestBudgetRejectsUnboundedResourceConfiguration(t *testing.T) {
	t.Parallel()

	tests := []Budget{
		{Timeout: 2*time.Minute + time.Nanosecond, MaxBytes: 1, MaxItems: 1, MaxTimeRange: time.Hour, MaxSamples: 1},
		{Timeout: time.Second, MaxBytes: (64 << 20) + 1, MaxItems: 1, MaxTimeRange: time.Hour, MaxSamples: 1},
		{Timeout: time.Second, MaxBytes: 1, MaxItems: 10_001, MaxTimeRange: time.Hour, MaxSamples: 1},
		{Timeout: time.Second, MaxBytes: 1, MaxItems: 1, MaxTimeRange: 24*time.Hour + time.Nanosecond, MaxSamples: 1},
		{Timeout: time.Second, MaxBytes: 1, MaxItems: 1, MaxTimeRange: time.Hour, MaxSamples: 1_000_001},
	}
	for _, budget := range tests {
		if err := budget.Validate(); err == nil {
			t.Fatalf("unbounded budget was accepted: %#v", budget)
		}
	}
}
