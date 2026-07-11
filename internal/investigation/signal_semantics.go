package investigation

import (
	"fmt"
	"regexp"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
)

const MaxSignalFutureSkew = 5 * time.Minute

const (
	maxSignalLabels     = 64
	maxSignalLabelValue = 512
)

var signalLabelKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}$`)

// NormalizeSignal validates an untrusted signal against a trusted clock,
// detaches labels and normalizes ObservedAt for stable repository replay.
func NormalizeSignal(signal domain.Signal, trustedNow time.Time) (domain.Signal, error) {
	now := trustedNow.Round(0).UTC()
	if now.IsZero() {
		return domain.Signal{}, fmt.Errorf("%w: trusted signal clock is required", ErrInvalidRequest)
	}
	normalized := signal
	normalized.ObservedAt = signal.ObservedAt.Round(0).UTC()
	normalized.Labels = cloneSignalLabels(signal.Labels)
	if err := normalized.Validate(); err != nil ||
		!domain.ValidResourceID(normalized.WorkspaceID) || !domain.ValidResourceID(normalized.ID) ||
		!domain.ValidResourceID(normalized.IntegrationID) || !domain.ValidSHA256Hex(normalized.PayloadHash) ||
		len(normalized.Labels) > maxSignalLabels || normalized.ObservedAt.After(now.Add(MaxSignalFutureSkew)) {
		return domain.Signal{}, fmt.Errorf("%w: invalid signal", ErrInvalidRequest)
	}
	for key, value := range normalized.Labels {
		if !signalLabelKeyPattern.MatchString(key) || len(value) > maxSignalLabelValue || !domain.ValidSafeMetadata(key, value) {
			return domain.Signal{}, fmt.Errorf("%w: invalid signal", ErrInvalidRequest)
		}
	}
	return normalized, nil
}

func cloneSignalLabels(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}
