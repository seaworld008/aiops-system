package connectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const MaxEvidenceQueryBytes = 8 << 10

type Budget struct {
	Timeout      time.Duration
	MaxBytes     int64
	MaxItems     int
	MaxTimeRange time.Duration
	MaxSamples   int
}

func DefaultBudget() Budget {
	return Budget{
		Timeout:      10 * time.Second,
		MaxBytes:     1 << 20,
		MaxItems:     500,
		MaxTimeRange: time.Hour,
		MaxSamples:   10_000,
	}
}

// WithDefaults preserves the original required transport limits while filling
// query-budget fields added after the initial connector contract.
func (budget Budget) WithDefaults() Budget {
	defaults := DefaultBudget()
	if budget.MaxTimeRange == 0 {
		budget.MaxTimeRange = defaults.MaxTimeRange
	}
	if budget.MaxSamples == 0 {
		budget.MaxSamples = defaults.MaxSamples
	}
	return budget
}

func (budget Budget) Validate() error {
	if budget.Timeout <= 0 || budget.MaxBytes <= 0 || budget.MaxItems <= 0 || budget.MaxTimeRange <= 0 || budget.MaxSamples <= 0 {
		return fmt.Errorf("connector budget values must be positive")
	}
	if budget.Timeout > 2*time.Minute || budget.MaxBytes > 64<<20 || budget.MaxItems > 10_000 || budget.MaxTimeRange > 24*time.Hour || budget.MaxSamples > 1_000_000 {
		return fmt.Errorf("connector budget exceeds platform safety limits")
	}
	return nil
}

type Result struct {
	Source      string
	Query       string
	CollectedAt time.Time
	ItemCount   int
	ContentHash string
	Truncated   bool
	Items       []json.RawMessage
}

// HashItems binds an evidence digest to exactly the projected and truncated
// items returned to callers. Upstream envelopes and discarded fields are not
// part of this contract.
func HashItems(items []json.RawMessage) (string, error) {
	encoded, err := json.Marshal(items)
	if err != nil {
		return "", fmt.Errorf("marshal evidence items: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func ValidateResult(result Result) error {
	if strings.TrimSpace(result.Source) == "" || len(result.Source) > 128 || strings.ContainsAny(result.Source, "\r\n\x00") {
		return fmt.Errorf("evidence source is invalid")
	}
	if len(result.Query) > MaxEvidenceQueryBytes || strings.ContainsAny(result.Query, "\x00") {
		return fmt.Errorf("evidence query exceeds its contract")
	}
	if result.CollectedAt.IsZero() {
		return fmt.Errorf("evidence collection time is required")
	}
	if result.ItemCount < 0 || result.ItemCount != len(result.Items) {
		return fmt.Errorf("evidence item count does not match returned items")
	}
	for _, item := range result.Items {
		if len(item) == 0 || !json.Valid(item) {
			return fmt.Errorf("evidence contains invalid JSON")
		}
	}
	expectedHash, err := HashItems(result.Items)
	if err != nil {
		return err
	}
	if result.ContentHash != expectedHash {
		return fmt.Errorf("evidence content hash does not match returned items")
	}
	return nil
}
