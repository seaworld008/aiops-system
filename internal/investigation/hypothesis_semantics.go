package investigation

import (
	"fmt"
	"math"
)

type ConfidenceBand string

const (
	ConfidenceLow    ConfidenceBand = "LOW"
	ConfidenceMedium ConfidenceBand = "MEDIUM"
	ConfidenceHigh   ConfidenceBand = "HIGH"
)

// ConfidenceBandFor is the single adapter boundary for the legacy
// confidence_band column. Its thresholds are mirrored by migration 000010.
func ConfidenceBandFor(confidence float64) (ConfidenceBand, error) {
	if math.IsNaN(confidence) || math.IsInf(confidence, 0) || confidence < 0 || confidence > 1 {
		return "", fmt.Errorf("%w: invalid hypothesis confidence", ErrInvalidRequest)
	}
	switch {
	case confidence < 0.5:
		return ConfidenceLow, nil
	case confidence < 0.8:
		return ConfidenceMedium, nil
	default:
		return ConfidenceHigh, nil
	}
}
