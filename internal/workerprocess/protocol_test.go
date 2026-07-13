package workerprocess

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/seaworld008/aiops-system/internal/readassembly"
)

func TestIsControlWorkerChildRequiresExactPrivateArgument(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "exact", args: []string{controlWorkerChildArgument}, want: true},
		{name: "none"},
		{name: "prefix", args: []string{"--aiops-internal-control-worker-child"}},
		{name: "extra", args: []string{controlWorkerChildArgument, "extra"}},
		{name: "duplicate", args: []string{controlWorkerChildArgument, controlWorkerChildArgument}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := IsControlWorkerChild(test.args); got != test.want {
				t.Fatalf("IsControlWorkerChild() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestIsControlWorkerSourceLoaderChildRequiresExactPrivateArgument(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		args []string
		want bool
	}{
		{args: []string{controlWorkerLoaderArgument}, want: true},
		{args: nil},
		{args: []string{"--aiops-internal-control-worker-source-loader"}},
		{args: []string{controlWorkerLoaderArgument, "extra"}},
	} {
		if got := IsControlWorkerSourceLoaderChild(test.args); got != test.want {
			t.Fatalf("IsControlWorkerSourceLoaderChild(%q) = %t, want %t", test.args, got, test.want)
		}
	}
}

func TestChildStatusReadyIsExactlyOnce(t *testing.T) {
	t.Parallel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	source := &testChildSource{}
	status := newChildStatus(writer, source)
	status.snapshotBuilt = true
	if err := ReportControlWorkerReady(status); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
	frame := make([]byte, 1)
	if read, err := reader.Read(frame); err != nil || read != 1 || frame[0] != controlWorkerReadyByte {
		t.Fatalf("status frame = (%q, %d, %v)", frame, read, err)
	}
	if err := ReportControlWorkerReady(status); err != errStatusAlreadyReported {
		t.Fatalf("second Ready() error = %v, want %v", err, errStatusAlreadyReported)
	}
	if err := CloseControlWorkerChild(status); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !source.closed {
		t.Fatal("Close() did not close inherited source")
	}
	if err := CloseControlWorkerChild(status); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestChildStatusCannotReportReadyBeforeSemanticSnapshot(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	status := newChildStatus(writer, &testChildSource{})
	if err := ReportControlWorkerReady(status); err != errStatusAlreadyReported {
		t.Fatalf("ReportControlWorkerReady(pre-snapshot) error = %v", err)
	}
	if err := CloseControlWorkerChild(status); err != nil {
		t.Fatalf("CloseControlWorkerChild() error = %v", err)
	}
	frame := make([]byte, 1)
	if read, err := reader.Read(frame); read != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("pre-snapshot status channel = read %d frame %q error %v; want EOF without READY", read, frame, err)
	}
}

func TestBuildControlWorkerSnapshotRejectsMissingOrPanickingSourceCapability(t *testing.T) {
	tests := map[string]ioCloserForSnapshotTest{
		"missing builder":   &testChildSource{},
		"panicking builder": &snapshotBuildTestSource{panicBuild: true},
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			status := newChildStatus(writer, source)
			snapshot, buildErr := BuildControlWorkerSnapshot(context.Background(), status)
			if snapshot != nil || buildErr != errInvalidChildInvocation {
				t.Fatalf("BuildControlWorkerSnapshot() = %#v, %v", snapshot, buildErr)
			}
			if err := CloseControlWorkerChild(status); err != nil {
				t.Fatalf("CloseControlWorkerChild() error = %v", err)
			}
		})
	}
}

func TestChildStatusCopyCannotDuplicateCapability(t *testing.T) {
	t.Parallel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	status := newChildStatus(writer, &testChildSource{})
	status.snapshotBuilt = true
	copied := &ChildStatus{
		file: status.file, state: status.state, seal: status.seal, self: status.self,
	}
	if err := ReportControlWorkerReady(copied); err != errInvalidStatusChannel {
		t.Fatalf("copied Ready() error = %v, want %v", err, errInvalidStatusChannel)
	}
	if err := CloseControlWorkerChild(copied); err != errInvalidStatusChannel {
		t.Fatalf("copied Close() error = %v, want %v", err, errInvalidStatusChannel)
	}
	if err := ReportControlWorkerReady(status); err != nil {
		t.Fatalf("original Ready() error = %v", err)
	}
	frame := make([]byte, 1)
	if read, err := reader.Read(frame); err != nil || read != 1 || frame[0] != controlWorkerReadyByte {
		t.Fatalf("original status frame = (%q, %d, %v)", frame, read, err)
	}
	if err := CloseControlWorkerChild(status); err != nil {
		t.Fatalf("original Close() error = %v", err)
	}
}

func TestChildStatusReadyAndCloseRaceKeepsOneLifecycle(t *testing.T) {
	for iteration := range 100 {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		source := &countingChildSource{}
		status := newChildStatus(writer, source)
		status.snapshotBuilt = true
		results := make(chan error, 2)
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			results <- ReportControlWorkerReady(status)
		}()
		go func() {
			defer wait.Done()
			results <- CloseControlWorkerChild(status)
		}()
		wait.Wait()
		close(results)
		for result := range results {
			if result != nil && result != errStatusAlreadyReported {
				t.Fatalf("iteration %d lifecycle error = %v", iteration, result)
			}
		}
		if got := source.closes.Load(); got != 1 {
			t.Fatalf("iteration %d source closes = %d, want 1", iteration, got)
		}
		_ = reader.Close()
	}
}

type testChildSource struct{ closed bool }

type ioCloserForSnapshotTest interface{ Close() error }

type snapshotBuildTestSource struct {
	panicBuild bool
	closed     bool
}

func (source *snapshotBuildTestSource) BuildSnapshot(context.Context) (*readassembly.Snapshot, error) {
	if source.panicBuild {
		panic("snapshot build test panic")
	}
	return nil, nil
}

func (source *snapshotBuildTestSource) Close() error {
	source.closed = true
	return nil
}

func (source *testChildSource) Close() error {
	source.closed = true
	return nil
}

type countingChildSource struct{ closes atomic.Int32 }

func (source *countingChildSource) Close() error {
	source.closes.Add(1)
	return nil
}

func TestSupervisorIsSingleUse(t *testing.T) {
	t.Parallel()
	supervisor := NewControlWorkerSupervisor()
	if supervisor == nil {
		t.Fatal("NewControlWorkerSupervisor() returned nil")
	}
	ctx, cancel := contextWithImmediateCancellation()
	defer cancel()
	if err := supervisor.Run(ctx); err != errInvalidSupervisor {
		t.Fatalf("canceled Run() error = %v, want %v", err, errInvalidSupervisor)
	}
	if err := supervisor.Run(ctx); err != errSupervisorRun {
		t.Fatalf("second Run() error = %v, want %v", err, errSupervisorRun)
	}
}

func TestSupervisorCopyAndZeroValueFailClosed(t *testing.T) {
	t.Parallel()
	original := NewControlWorkerSupervisor()
	copied := &ControlWorkerSupervisor{
		settings: original.settings, seal: original.seal, self: original.self,
	}
	if err := copied.Run(context.Background()); err != errInvalidSupervisor {
		t.Fatalf("copied Run() error = %v, want %v", err, errInvalidSupervisor)
	}
	if err := new(ControlWorkerSupervisor).Run(context.Background()); err != errInvalidSupervisor {
		t.Fatalf("zero-value Run() error = %v, want %v", err, errInvalidSupervisor)
	}
}

func contextWithImmediateCancellation() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, cancel
}
