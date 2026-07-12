package readassembly

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLoadFilesRejectsInvalidContextAndEmptyOptionsWithoutLeakingInput(t *testing.T) {
	const canary = "READ-SNAPSHOT-OPTION-CANARY"
	tests := []struct {
		name string
		ctx  context.Context
		want error
	}{
		{name: "nil context", ctx: nil, want: ErrSnapshotRejected},
		{name: "typed nil context", ctx: (*snapshotNilContext)(nil), want: ErrSnapshotRejected},
		{name: "panicking context", ctx: snapshotPanicContext{}, want: ErrSnapshotRejected},
		{name: "arbitrary context error", ctx: snapshotErrorContext{err: errors.New(canary)}, want: ErrSnapshotRejected},
		{name: "wrapped cancellation", ctx: snapshotErrorContext{err: fmt.Errorf("%s: %w", canary, context.Canceled)}, want: ErrSnapshotRejected},
		{name: "wrapped deadline", ctx: snapshotErrorContext{err: fmt.Errorf("%s: %w", canary, context.DeadlineExceeded)}, want: ErrSnapshotRejected},
		{name: "empty options", ctx: context.Background(), want: ErrSnapshotRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := LoadFiles(test.ctx, FileOptions{ConnectorManifestFile: canary})
			if snapshot != nil || !errors.Is(err, test.want) {
				t.Fatalf("LoadFiles() = %#v, %v; want nil, %v", snapshot, err, test.want)
			}
			if strings.Contains(fmt.Sprint(err), canary) {
				t.Fatalf("LoadFiles() leaked option material: %v", err)
			}
		})
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if snapshot, err := LoadFiles(cancelled, FileOptions{}); snapshot != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("LoadFiles(cancelled) = %#v, %v", snapshot, err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if snapshot, err := LoadFiles(expired, FileOptions{}); snapshot != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("LoadFiles(expired) = %#v, %v", snapshot, err)
	}
}

func TestSnapshotContextErrorsAreCanonicalAndLowSensitive(t *testing.T) {
	const canary = "READ-SNAPSHOT-CONTEXT-ERROR-CANARY"
	tests := []struct {
		name string
		ctx  context.Context
		want error
	}{
		{name: "active", ctx: context.Background(), want: nil},
		{name: "canonical canceled", ctx: snapshotErrorContext{err: context.Canceled}, want: context.Canceled},
		{name: "canonical deadline", ctx: snapshotErrorContext{err: context.DeadlineExceeded}, want: context.DeadlineExceeded},
		{name: "arbitrary", ctx: snapshotErrorContext{err: errors.New(canary)}, want: ErrSnapshotRejected},
		{name: "wrapped canceled", ctx: snapshotErrorContext{err: fmt.Errorf("%s: %w", canary, context.Canceled)}, want: ErrSnapshotRejected},
		{name: "wrapped deadline", ctx: snapshotErrorContext{err: fmt.Errorf("%s: %w", canary, context.DeadlineExceeded)}, want: ErrSnapshotRejected},
		{name: "panic", ctx: snapshotPanicContext{}, want: ErrSnapshotRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := snapshotContextError(test.ctx)
			if err != test.want {
				t.Fatalf("snapshotContextError() = %v; want exact %v", err, test.want)
			}
			if strings.Contains(fmt.Sprint(err), canary) {
				t.Fatalf("snapshotContextError() leaked context material: %v", err)
			}
		})
	}
}

type snapshotNilContext struct{}

func (*snapshotNilContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*snapshotNilContext) Done() <-chan struct{}       { return nil }
func (*snapshotNilContext) Err() error                  { return nil }
func (*snapshotNilContext) Value(any) any               { return nil }

type snapshotPanicContext struct{}

func (snapshotPanicContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (snapshotPanicContext) Done() <-chan struct{}       { return nil }
func (snapshotPanicContext) Err() error                  { panic("READ-SNAPSHOT-CONTEXT-CANARY") }
func (snapshotPanicContext) Value(any) any               { return nil }

type snapshotErrorContext struct{ err error }

func (snapshotErrorContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (snapshotErrorContext) Done() <-chan struct{}       { return nil }
func (context snapshotErrorContext) Err() error          { return context.err }
func (snapshotErrorContext) Value(any) any               { return nil }
