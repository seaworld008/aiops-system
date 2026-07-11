package investigation_test

import (
	"errors"
	"math"
	"testing"

	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestConfidenceBandForUsesFrozenPostgresBoundaries(t *testing.T) {
	for _, testCase := range []struct {
		confidence float64
		want       investigation.ConfidenceBand
	}{
		{confidence: 0, want: investigation.ConfidenceLow},
		{confidence: math.Nextafter(0.5, 0), want: investigation.ConfidenceLow},
		{confidence: 0.5, want: investigation.ConfidenceMedium},
		{confidence: math.Nextafter(0.8, 0), want: investigation.ConfidenceMedium},
		{confidence: 0.8, want: investigation.ConfidenceHigh},
		{confidence: 1, want: investigation.ConfidenceHigh},
	} {
		got, err := investigation.ConfidenceBandFor(testCase.confidence)
		if err != nil || got != testCase.want {
			t.Fatalf("ConfidenceBandFor(%v) = %q, %v; want %q, nil",
				testCase.confidence, got, err, testCase.want)
		}
	}
}

func TestConfidenceBandForRejectsNonFiniteAndOutOfRangeValues(t *testing.T) {
	for _, confidence := range []float64{-math.SmallestNonzeroFloat64, math.Nextafter(1, 2), math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := investigation.ConfidenceBandFor(confidence); !errors.Is(err, investigation.ErrInvalidRequest) {
			t.Fatalf("ConfidenceBandFor(%v) error = %v, want ErrInvalidRequest", confidence, err)
		}
	}
}
