package leasefence

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
)

const redactedFence = "[REDACTED_LEASE_FENCE]"

var (
	errSerializationDisabled = errors.New("lease fence serialization is disabled")
	canonicalRunIDPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	canonicalOwnerPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
)

// Fence is a process-local, non-serializable proof that binds one claimed run.
// Copies deliberately share state so destroying any copy invalidates all copies.
type Fence struct {
	state *sharedState
}

type sharedState struct {
	mu     sync.Mutex
	runID  string
	owner  string
	epoch  int64
	token  [32]byte
	active bool
}

func FromManualRun(runID, owner string, epoch int64, rawToken *[32]byte) (Fence, error) {
	return consume(runID, owner, epoch, rawToken)
}

func FromQueueClaim(runID, owner string, epoch int64, rawToken *[32]byte) (Fence, error) {
	return consume(runID, owner, epoch, rawToken)
}

func consume(runID, owner string, epoch int64, rawToken *[32]byte) (Fence, error) {
	if rawToken == nil {
		return Fence{}, errors.New("lease fence token is required")
	}
	token := *rawToken
	clear(rawToken[:])
	if !canonicalRunIDPattern.MatchString(runID) || !canonicalOwnerPattern.MatchString(owner) || epoch <= 0 {
		clear(token[:])
		return Fence{}, errors.New("lease fence coordinates are invalid")
	}
	return Fence{state: &sharedState{
		runID: runID, owner: owner, epoch: epoch, token: token, active: true,
	}}, nil
}

func (fence Fence) Matches(runID, owner string, epoch int64, persistedTokenSHA256 string) bool {
	if fence.state == nil || len(persistedTokenSHA256) != sha256.Size*2 ||
		persistedTokenSHA256 != strings.ToLower(persistedTokenSHA256) {
		return false
	}
	var persisted [sha256.Size]byte
	decoded, err := hex.Decode(persisted[:], []byte(persistedTokenSHA256))
	if err != nil || decoded != len(persisted) {
		return false
	}

	fence.state.mu.Lock()
	defer fence.state.mu.Unlock()
	if !fence.state.active || fence.state.runID != runID || fence.state.owner != owner || fence.state.epoch != epoch {
		return false
	}
	actual := sha256.Sum256(fence.state.token[:])
	return subtle.ConstantTimeCompare(actual[:], persisted[:]) == 1
}

func (fence Fence) Destroy() {
	if fence.state == nil {
		return
	}
	fence.state.mu.Lock()
	defer fence.state.mu.Unlock()
	fence.state.runID = ""
	fence.state.owner = ""
	fence.state.epoch = 0
	clear(fence.state.token[:])
	fence.state.active = false
}

func (Fence) MarshalJSON() ([]byte, error)   { return nil, errSerializationDisabled }
func (*Fence) UnmarshalJSON([]byte) error    { return errSerializationDisabled }
func (Fence) MarshalText() ([]byte, error)   { return nil, errSerializationDisabled }
func (*Fence) UnmarshalText([]byte) error    { return errSerializationDisabled }
func (Fence) MarshalBinary() ([]byte, error) { return nil, errSerializationDisabled }
func (*Fence) UnmarshalBinary([]byte) error  { return errSerializationDisabled }
func (Fence) String() string                 { return redactedFence }
func (Fence) GoString() string               { return redactedFence }
func (Fence) LogValue() slog.Value           { return slog.StringValue(redactedFence) }
func (Fence) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redactedFence) }
