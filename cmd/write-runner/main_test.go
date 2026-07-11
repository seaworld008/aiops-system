package main

import (
	"context"
	"errors"
	"testing"
)

type capabilityStub struct {
	closed   bool
	closeErr error
}

func (stub *capabilityStub) Close() error {
	stub.closed = true
	return stub.closeErr
}

func TestRunNeverProbesOrClaimsWhenDisabled(t *testing.T) {
	for _, mode := range []string{"", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			probed := false
			err := run(ctx, nil, mode, func() error { return nil }, func() (capabilityHandle, error) {
				probed = true
				return &capabilityStub{}, nil
			})
			if err != nil || probed {
				t.Fatalf("run(disabled) = %v, probed=%t", err, probed)
			}
		})
	}
}

func TestRunNonProductionFailsClosedOnIsolationCapability(t *testing.T) {
	capabilityError := errors.New("capability unavailable")
	if err := run(context.Background(), nil, "non-production", func() error { return nil }, func() (capabilityHandle, error) {
		return nil, capabilityError
	}); !errors.Is(err, capabilityError) {
		t.Fatalf("run(non-production) error = %v", err)
	}
}

func TestRunNonProductionHardensBeforeCapabilityProbeAndFailsClosed(t *testing.T) {
	hardeningError := errors.New("hardening unavailable")
	probed := false
	if err := run(context.Background(), nil, "non-production", func() error { return hardeningError }, func() (capabilityHandle, error) {
		probed = true
		return &capabilityStub{}, nil
	}); !errors.Is(err, hardeningError) || probed {
		t.Fatalf("run(hardening failure) = %v, probed=%t", err, probed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	order := make([]string, 0, 2)
	capability := &capabilityStub{}
	if err := run(ctx, nil, "non-production", func() error {
		order = append(order, "harden")
		return nil
	}, func() (capabilityHandle, error) {
		order = append(order, "probe")
		return capability, nil
	}); err != nil || len(order) != 2 || order[0] != "harden" || order[1] != "probe" || !capability.closed {
		t.Fatalf("run(order) = %v, order=%v, closed=%t", err, order, capability.closed)
	}
}

func TestRunNonProductionWaitsOnlyAfterCapabilityProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probes := 0
	if err := run(ctx, nil, "non-production", func() error { return nil }, func() (capabilityHandle, error) {
		probes++
		return &capabilityStub{}, nil
	}); err != nil || probes != 1 {
		t.Fatalf("run(non-production) = %v, probes=%d", err, probes)
	}
}

func TestRunRejectsProductionAliasesAndArguments(t *testing.T) {
	for _, mode := range []string{"production", "prod", "enabled", "true", "NON-PRODUCTION"} {
		if err := run(context.Background(), nil, mode, func() error { return nil }, func() (capabilityHandle, error) {
			return nil, nil
		}); !errors.Is(err, errInvalidMode) {
			t.Fatalf("run(%q) error = %v", mode, err)
		}
	}
	if err := run(context.Background(), []string{"--executor=/tmp/payload"}, "disabled", func() error { return nil }, func() (capabilityHandle, error) {
		return nil, nil
	}); !errors.Is(err, errInvalidInvocation) {
		t.Fatalf("run(argument) error = %v", err)
	}
}

func TestRunRejectsNilCapabilityAndPropagatesCloseFailure(t *testing.T) {
	if err := run(context.Background(), nil, "non-production", func() error { return nil }, func() (capabilityHandle, error) {
		return nil, nil
	}); !errors.Is(err, errInvalidInvocation) {
		t.Fatalf("run(nil capability) error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	closeError := errors.New("close capability")
	capability := &capabilityStub{closeErr: closeError}
	if err := run(ctx, nil, "non-production", func() error { return nil }, func() (capabilityHandle, error) {
		return capability, nil
	}); !errors.Is(err, closeError) || !capability.closed {
		t.Fatalf("run(close failure) = %v, closed=%t", err, capability.closed)
	}
}
