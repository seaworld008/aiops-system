package investigation

import (
	"context"
	"fmt"
	"io"
	"regexp"

	"github.com/seaworld008/aiops-system/internal/domain"
)

var persistentSignalIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)

func ValidPersistentSignalID(value string) bool { return persistentSignalIDPattern.MatchString(value) }

// RegisteredSignal is a detached signal plus the tenant/workspace identity
// recovered from trusted persistence. Workflow input is never a selector for
// this scope.
type RegisteredSignal struct {
	TenantID    string
	WorkspaceID string
	Signal      domain.Signal
}

func (RegisteredSignal) String() string   { return "RegisteredSignal{[REDACTED]}" }
func (RegisteredSignal) GoString() string { return "RegisteredSignal{[REDACTED]}" }
func (registered RegisteredSignal) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, registered.String())
}
func (RegisteredSignal) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*RegisteredSignal) UnmarshalJSON([]byte) error  { return ErrInvalidRequest }

func (registered RegisteredSignal) Validate() error {
	if !persistentSignalIDPattern.MatchString(registered.TenantID) ||
		!persistentSignalIDPattern.MatchString(registered.WorkspaceID) ||
		registered.Signal.WorkspaceID != registered.WorkspaceID {
		return ErrInvalidRequest
	}
	if _, err := NormalizeSignalForReplay(registered.Signal); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

// SignalRegistrationReader resolves a globally persistent signal ID. It is a
// deliberately narrow Activity boundary and is not part of the broad mutable
// investigation Repository contract.
type SignalRegistrationReader interface {
	GetRegisteredSignal(context.Context, string) (RegisteredSignal, error)
}
