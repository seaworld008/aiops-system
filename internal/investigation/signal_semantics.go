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

// NormalizeSignal validates an untrusted signal for a new write, detaches
// labels and normalizes ObservedAt for stable repository replay.
func NormalizeSignal(signal domain.Signal, trustedNow time.Time) (domain.Signal, error) {
	normalized, err := NormalizeSignalForReplay(signal)
	if err != nil {
		return domain.Signal{}, err
	}
	if err := ValidateNewSignalTime(normalized, trustedNow); err != nil {
		return domain.Signal{}, err
	}
	return normalized, nil
}

// NormalizeSignalForReplay applies only immutable shape and security rules.
// Repositories use it before freshness admission so an already accepted fact
// remains replayable if the trusted wall clock later moves backward.
func NormalizeSignalForReplay(signal domain.Signal) (domain.Signal, error) {
	normalized := signal
	normalized.ObservedAt = signal.ObservedAt.Round(0).UTC()
	normalized.Labels = cloneSignalLabels(signal.Labels)
	if err := normalized.Validate(); err != nil ||
		!domain.ValidResourceID(normalized.WorkspaceID) || !domain.ValidResourceID(normalized.ID) ||
		!domain.ValidResourceID(normalized.IntegrationID) || !domain.ValidSHA256Hex(normalized.PayloadHash) ||
		len(normalized.Labels) > maxSignalLabels {
		return domain.Signal{}, fmt.Errorf("%w: invalid signal", ErrInvalidRequest)
	}
	for key, value := range normalized.Labels {
		if !signalLabelKeyPattern.MatchString(key) || len(value) > maxSignalLabelValue || !domain.ValidSafeMetadata(key, value) {
			return domain.Signal{}, fmt.Errorf("%w: invalid signal", ErrInvalidRequest)
		}
	}
	return normalized, nil
}

// ValidateNewSignalTime applies the mutable trusted-clock admission rule only
// to a signal that does not already exist in the repository.
func ValidateNewSignalTime(signal domain.Signal, trustedNow time.Time) error {
	now := trustedNow.Round(0).UTC()
	if now.IsZero() || signal.ObservedAt.IsZero() || signal.ObservedAt.After(now.Add(MaxSignalFutureSkew)) {
		return fmt.Errorf("%w: invalid signal", ErrInvalidRequest)
	}
	return nil
}

func cloneSignalLabels(source map[string]string) map[string]string {
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}
