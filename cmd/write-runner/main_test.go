package main

import (
	"context"
	"errors"
	"testing"
)

func TestRunNeverProbesOrClaimsWhenDisabled(t *testing.T) {
	for _, mode := range []string{"", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			probed := false
			err := run(ctx, nil, mode, func() error { return nil }, func() error {
				probed = true
				return nil
			})
			if err != nil || probed {
				t.Fatalf("run(disabled) = %v, probed=%t", err, probed)
			}
		})
	}
}

func TestRunNonProductionFailsClosedOnIsolationCapability(t *testing.T) {
	capabilityError := errors.New("capability unavailable")
	if err := run(context.Background(), nil, "non-production", func() error { return nil }, func() error { return capabilityError }); !errors.Is(err, capabilityError) {
		t.Fatalf("run(non-production) error = %v", err)
	}
}

func TestRunNonProductionHardensBeforeCapabilityProbeAndFailsClosed(t *testing.T) {
	hardeningError := errors.New("hardening unavailable")
	probed := false
	if err := run(context.Background(), nil, "non-production", func() error { return hardeningError }, func() error {
		probed = true
		return nil
	}); !errors.Is(err, hardeningError) || probed {
		t.Fatalf("run(hardening failure) = %v, probed=%t", err, probed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	order := make([]string, 0, 2)
	if err := run(ctx, nil, "non-production", func() error {
		order = append(order, "harden")
		return nil
	}, func() error {
		order = append(order, "probe")
		return nil
	}); err != nil || len(order) != 2 || order[0] != "harden" || order[1] != "probe" {
		t.Fatalf("run(order) = %v, order=%v", err, order)
	}
}

func TestRunNonProductionWaitsOnlyAfterCapabilityProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probes := 0
	if err := run(ctx, nil, "non-production", func() error { return nil }, func() error { probes++; return nil }); err != nil || probes != 1 {
		t.Fatalf("run(non-production) = %v, probes=%d", err, probes)
	}
}

func TestRunRejectsProductionAliasesAndArguments(t *testing.T) {
	for _, mode := range []string{"production", "prod", "enabled", "true", "NON-PRODUCTION"} {
		if err := run(context.Background(), nil, mode, func() error { return nil }, func() error { return nil }); !errors.Is(err, errInvalidMode) {
			t.Fatalf("run(%q) error = %v", mode, err)
		}
	}
	if err := run(context.Background(), []string{"--executor=/tmp/payload"}, "disabled", func() error { return nil }, func() error { return nil }); !errors.Is(err, errInvalidInvocation) {
		t.Fatalf("run(argument) error = %v", err)
	}
}
