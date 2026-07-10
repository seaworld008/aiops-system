package connectors

import (
	"encoding/json"
	"fmt"
	"time"
)

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
