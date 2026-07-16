// Package discoverylimit defines the durable, fail-closed admission boundary
// for discovery Provider calls. Its values contain only safe coordinates and
// receipt metadata; database handles and SQL never cross this interface.
package discoverylimit

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/domain"
)

const (
	MaxRateLimitRequests      int64 = 1_000_000
	MaxRateLimitWindowSeconds int64 = 86_400
	MaxPermitTTL                    = time.Hour
)

var (
	ErrInvalidRequest = errors.New("discovery limiter request invalid")
	ErrIneligible     = errors.New("discovery limiter coordinates ineligible")
	ErrLimited        = errors.New("discovery limiter capacity unavailable")
	ErrStalePermit    = errors.New("discovery limiter permit stale")
	ErrIdempotency    = errors.New("discovery limiter idempotency conflict")
	ErrStateConflict  = errors.New("discovery limiter state conflict")
	ErrUnavailable    = errors.New("discovery limiter unavailable")

	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	providerPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	reasonPattern   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
)

// Limiter owns the append-only permit lifecycle. Every method binds one exact
// Scope, Source, Run, and Provider tuple.
type Limiter interface {
	Acquire(context.Context, AcquireCommand) (Permit, error)
	Release(context.Context, ReleaseCommand) (Receipt, error)
	Delay(context.Context, DelayCommand) (Receipt, error)
}

type Coordinates struct {
	Scope        assetcatalog.SourceScope
	SourceID     string
	RunID        string
	ProviderKind string
}

func (value Coordinates) Valid() bool {
	return value.Scope.Valid() && uuidPattern.MatchString(value.SourceID) &&
		uuidPattern.MatchString(value.RunID) && providerPattern.MatchString(value.ProviderKind)
}

type AcquireCommand struct {
	Coordinates Coordinates
	RequestID   string
	TTL         time.Duration
}

func (command AcquireCommand) Validate() error {
	if !command.Coordinates.Valid() || !validRequestID(command.RequestID) ||
		command.TTL <= 0 || command.TTL > MaxPermitTTL ||
		command.TTL%time.Microsecond != 0 {
		return ErrInvalidRequest
	}
	return nil
}

type ReleaseCommand struct {
	Coordinates Coordinates
	PermitID    string
	RequestID   string
	ReasonCode  string
}

func (command ReleaseCommand) Validate() error {
	if !command.Coordinates.Valid() || !uuidPattern.MatchString(command.PermitID) ||
		!validRequestID(command.RequestID) ||
		!reasonPattern.MatchString(command.ReasonCode) {
		return ErrInvalidRequest
	}
	return nil
}

type DelayCommand struct {
	Coordinates Coordinates
	PermitID    string
	RequestID   string
	ReasonCode  string
	NotBefore   time.Time
}

func (command DelayCommand) Validate() error {
	if !command.Coordinates.Valid() || !uuidPattern.MatchString(command.PermitID) ||
		!validRequestID(command.RequestID) ||
		!reasonPattern.MatchString(command.ReasonCode) ||
		!validTimestamp(command.NotBefore) {
		return ErrInvalidRequest
	}
	return nil
}

type Permit struct {
	PermitID      string
	Coordinates   Coordinates
	RequestID     string
	CommandSHA256 string
	ReceiptSHA256 string
	AcquiredAt    time.Time
	ExpiresAt     time.Time
}

func (permit Permit) Valid() bool {
	return uuidPattern.MatchString(permit.PermitID) && permit.Coordinates.Valid() &&
		domain.ValidIdempotencyKey(permit.RequestID) &&
		domain.ValidSHA256Hex(permit.CommandSHA256) &&
		domain.ValidSHA256Hex(permit.ReceiptSHA256) &&
		validTimestamp(permit.AcquiredAt) && validTimestamp(permit.ExpiresAt) &&
		permit.ExpiresAt.After(permit.AcquiredAt) &&
		permit.ExpiresAt.Sub(permit.AcquiredAt) <= MaxPermitTTL
}

type ReceiptKind string

const (
	ReceiptRelease ReceiptKind = "RELEASE"
	ReceiptDelay   ReceiptKind = "DELAY"
	ReceiptExpire  ReceiptKind = "EXPIRE"
)

func (kind ReceiptKind) Valid() bool {
	return kind == ReceiptRelease || kind == ReceiptDelay || kind == ReceiptExpire
}

type Receipt struct {
	ReceiptID     string
	PermitID      string
	Kind          ReceiptKind
	Coordinates   Coordinates
	RequestID     string
	CommandSHA256 string
	ReceiptSHA256 string
	AcquiredAt    time.Time
	ExpiresAt     time.Time
	NotBefore     *time.Time
	ReasonCode    string
}

func (receipt Receipt) Clone() Receipt {
	if receipt.NotBefore != nil {
		value := *receipt.NotBefore
		receipt.NotBefore = &value
	}
	return receipt
}

func (receipt Receipt) Valid() bool {
	if !uuidPattern.MatchString(receipt.ReceiptID) ||
		!uuidPattern.MatchString(receipt.PermitID) ||
		receipt.ReceiptID == receipt.PermitID || !receipt.Kind.Valid() ||
		!receipt.Coordinates.Valid() ||
		!domain.ValidIdempotencyKey(receipt.RequestID) ||
		!domain.ValidSHA256Hex(receipt.CommandSHA256) ||
		!domain.ValidSHA256Hex(receipt.ReceiptSHA256) ||
		!validTimestamp(receipt.AcquiredAt) || !validTimestamp(receipt.ExpiresAt) ||
		!receipt.ExpiresAt.After(receipt.AcquiredAt) ||
		receipt.ExpiresAt.Sub(receipt.AcquiredAt) > MaxPermitTTL ||
		!reasonPattern.MatchString(receipt.ReasonCode) {
		return false
	}
	switch receipt.Kind {
	case ReceiptDelay:
		return receipt.NotBefore != nil && validTimestamp(*receipt.NotBefore) &&
			receipt.NotBefore.After(receipt.AcquiredAt)
	case ReceiptRelease, ReceiptExpire:
		return receipt.NotBefore == nil
	default:
		return false
	}
}

func validTimestamp(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC &&
		value.Year() >= 2000 && value.Year() <= 9999 &&
		value.Nanosecond()%1000 == 0 && value == value.Round(0)
}

func validRequestID(value string) bool {
	return domain.ValidIdempotencyKey(value) && !strings.HasPrefix(value, "limiter-expire:")
}
