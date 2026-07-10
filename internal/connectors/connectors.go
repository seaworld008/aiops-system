package connectors

import (
	"encoding/json"
	"fmt"
	"time"
)

type Budget struct {
	Timeout  time.Duration
	MaxBytes int64
	MaxItems int
}

func DefaultBudget() Budget {
	return Budget{
		Timeout:  10 * time.Second,
		MaxBytes: 1 << 20,
		MaxItems: 500,
	}
}

func (budget Budget) Validate() error {
	if budget.Timeout <= 0 || budget.MaxBytes <= 0 || budget.MaxItems <= 0 {
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
