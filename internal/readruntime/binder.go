// Package readruntime composes immutable connector, target, and executor
// contracts into the trusted component digests persisted for each READ task.
package readruntime

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
	"github.com/seaworld008/aiops-system/internal/readtarget"
)

var ErrBindingRejected = errors.New("READ task runtime binding rejected")

type binderSeal struct{ value byte }

var trustedBinderSeal = &binderSeal{value: 1}

// Binder owns only immutable, process-local registries and a fixed executor
// profile. It cannot choose a repository timestamp or aggregate RuntimeDigest.
type Binder struct {
	connectors *readconnector.Registry
	targets    *readtarget.Registry
	profile    *readexecutor.Profile
	seal       *binderSeal
	self       *Binder
}

func NewBinder(
	connectors *readconnector.Registry,
	targets *readtarget.Registry,
	profile *readexecutor.Profile,
) (*Binder, error) {
	if connectors == nil || !connectors.Ready() || targets == nil || !targets.Ready() ||
		profile == nil || !profile.Ready() {
		return nil, ErrBindingRejected
	}
	created := &Binder{
		connectors: connectors, targets: targets, profile: profile, seal: trustedBinderSeal,
	}
	created.self = created
	return created, nil
}

func (binder *Binder) Ready() bool {
	return binder != nil && binder.self == binder && binder.seal == trustedBinderSeal &&
		binder.connectors != nil && binder.connectors.Ready() && binder.targets != nil && binder.targets.Ready() &&
		binder.profile != nil && binder.profile.Ready()
}

// Bind implements investigation.TaskRuntimeBinder. Repository callers must
// continue to invoke it through ResolveTaskRuntimeComponents, which validates
// the complete canonical task set and selected Plan TasksHash before calling
// this per-task resolver.
func (binder *Binder) Bind(
	ctx context.Context,
	scope investigation.TaskSpecScope,
	plan domain.InvestigationPlanBinding,
	spec investigation.TaskSpec,
) (components investigation.TaskRuntimeComponents, returnedErr error) {
	defer func() {
		if recover() != nil {
			components = investigation.TaskRuntimeComponents{}
			if err := binderContextError(ctx); errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				returnedErr = err
			} else {
				returnedErr = ErrBindingRejected
			}
		}
	}()
	if err := binderContextError(ctx); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return investigation.TaskRuntimeComponents{}, err
		}
		return investigation.TaskRuntimeComponents{}, ErrBindingRejected
	}
	if !binder.Ready() || scope.Validate() != nil || scope.MappingStatus != domain.MappingExact ||
		plan.Validate() != nil || !canonicalTaskSpec(spec) {
		return investigation.TaskRuntimeComponents{}, ErrBindingRejected
	}
	if subtle.ConstantTimeCompare([]byte(plan.RegistryDigest), []byte(binder.connectors.Digest())) != 1 {
		return investigation.TaskRuntimeComponents{}, ErrBindingRejected
	}
	execution, err := binder.connectors.ResolveTaskSpec(ctx, scope, spec)
	if err != nil {
		return investigation.TaskRuntimeComponents{}, bindingError(ctx, err)
	}
	if !binder.profile.Supports(execution.Kind(), execution.Operation()) {
		return investigation.TaskRuntimeComponents{}, ErrBindingRejected
	}
	target, err := binder.targets.Resolve(ctx, scope, execution.Kind(), execution.TargetRef())
	if err != nil {
		return investigation.TaskRuntimeComponents{}, bindingError(ctx, err)
	}
	components = investigation.TaskRuntimeComponents{
		ConnectorDigest: strings.Clone(execution.ContractDigest()),
		TargetDigest:    strings.Clone(target.Digest()),
		ExecutorDigest:  strings.Clone(binder.profile.Digest()),
	}
	if components.Validate() != nil || !domain.ConnectorDigestMatchesID(spec.ConnectorID, components.ConnectorDigest) ||
		!referenceDigestMatches(execution.TargetRef(), components.TargetDigest) {
		return investigation.TaskRuntimeComponents{}, ErrBindingRejected
	}
	if err := binderContextError(ctx); err != nil {
		return investigation.TaskRuntimeComponents{}, err
	}
	return components, nil
}

func binderContextError(ctx context.Context) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = ErrBindingRejected
		}
	}()
	if ctx == nil {
		return ErrBindingRejected
	}
	value := reflect.ValueOf(ctx)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return ErrBindingRejected
		}
	}
	return ctx.Err()
}

func canonicalTaskSpec(spec investigation.TaskSpec) bool {
	canonical, _, err := investigation.CanonicalTaskSpecs([]investigation.TaskSpec{spec})
	return err == nil && len(canonical) == 1 && canonical[0].Key == spec.Key &&
		canonical[0].ConnectorID == spec.ConnectorID && canonical[0].Operation == spec.Operation &&
		bytes.Equal(canonical[0].Input, spec.Input)
}

func referenceDigestMatches(reference, digest string) bool {
	if len(reference) < len(digest) || !domain.ValidSHA256Hex(digest) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(reference[len(reference)-len(digest):]), []byte(digest)) == 1
}

func bindingError(ctx context.Context, err error) error {
	if contextErr := binderContextError(ctx); errors.Is(contextErr, context.Canceled) ||
		errors.Is(contextErr, context.DeadlineExceeded) {
		return contextErr
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrBindingRejected
}

func (Binder) String() string   { return "<aiops-read-runtime-binder>" }
func (Binder) GoString() string { return "<aiops-read-runtime-binder>" }
func (Binder) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-read-runtime-binder>")
}
func (Binder) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Binder) UnmarshalJSON([]byte) error  { return ErrBindingRejected }
