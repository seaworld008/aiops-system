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

func TestIsControlWorkerSecretLoaderChildRequiresExactPrivateArgument(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		args []string
		want bool
	}{
		{args: []string{controlWorkerSecretLoaderArgument}, want: true},
		{args: nil},
		{args: []string{"--aiops-internal-control-worker-secret-loader"}},
		{args: []string{controlWorkerLoaderArgument}},
		{args: []string{controlWorkerSecretLoaderArgument, "extra"}},
	} {
		if got := IsControlWorkerSecretLoaderChild(test.args); got != test.want {
			t.Fatalf("IsControlWorkerSecretLoaderChild(%q) = %t, want %t", test.args, got, test.want)
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
	if err := ReportControlWorkerSecretReady(status); err != nil {
		t.Fatalf("SecretReady() error = %v", err)
	}
	if err := BindControlWorkerSecrets(context.Background(), status); err != nil {
		t.Fatalf("BindControlWorkerSecrets() error = %v", err)
	}
	if err := ReportControlWorkerReady(status); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
	frame := make([]byte, 2)
	if read, err := io.ReadFull(reader, frame); err != nil || read != 2 || string(frame) != "SR" {
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

func TestChildStatusSecretReadyRequiresSnapshotAndIsExactlyOnce(t *testing.T) {
	t.Parallel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	status := newChildStatus(writer, &testChildSource{})

	if err := ReportControlWorkerSecretReady(status); err != errStatusAlreadyReported {
		t.Fatalf("SecretReady(pre-snapshot) error = %v, want %v", err, errStatusAlreadyReported)
	}
	status.snapshotBuilt = true
	if err := ReportControlWorkerSecretReady(status); err != nil {
		t.Fatalf("SecretReady() error = %v", err)
	}
	if err := ReportControlWorkerSecretReady(status); err != errStatusAlreadyReported {
		t.Fatalf("second SecretReady() error = %v, want %v", err, errStatusAlreadyReported)
	}
	frame := make([]byte, 1)
	if read, err := reader.Read(frame); err != nil || read != 1 || frame[0] != controlWorkerSecretReadyByte {
		t.Fatalf("secret-ready frame = (%q, %d, %v)", frame, read, err)
	}
	if frame[0] == controlWorkerReadyByte {
		t.Fatal("SECRET_READY was indistinguishable from READY")
	}
	if err := CloseControlWorkerChild(status); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestChildStatusReadyRequiresValidatedSecrets(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		prepare func(*ChildStatus) error
	}{
		{name: "before secret ready", prepare: func(*ChildStatus) error { return nil }},
		{name: "before secret binding", prepare: ReportControlWorkerSecretReady},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			status := newChildStatus(writer, &testChildSource{})
			status.snapshotBuilt = true
			if err := test.prepare(status); err != nil {
				t.Fatalf("prepare error = %v", err)
			}
			if err := ReportControlWorkerReady(status); err != errStatusAlreadyReported {
				t.Fatalf("Ready() error = %v, want %v", err, errStatusAlreadyReported)
			}
			if err := CloseControlWorkerChild(status); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			frames, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if len(frames) > 1 || (len(frames) == 1 && frames[0] != controlWorkerSecretReadyByte) {
				t.Fatalf("unexpected status frames %q", frames)
			}
			if len(frames) != 0 && frames[len(frames)-1] == controlWorkerReadyByte {
				t.Fatalf("READY emitted before validated secret binding: %q", frames)
			}
		})
	}
}

func TestBindControlWorkerSecretsIsOneShotAndDoesNotExposeSecretMaterial(t *testing.T) {
	t.Parallel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	source := &testChildSource{}
	status := newChildStatus(writer, source)
	status.snapshotBuilt = true
	if err := BindControlWorkerSecrets(context.Background(), status); err != errStatusAlreadyReported {
		t.Fatalf("BindControlWorkerSecrets(pre-barrier) error = %v, want %v", err, errStatusAlreadyReported)
	}
	if err := ReportControlWorkerSecretReady(status); err != nil {
		t.Fatalf("SecretReady() error = %v", err)
	}
	if err := BindControlWorkerSecrets(context.Background(), status); err != nil {
		t.Fatalf("BindControlWorkerSecrets() error = %v", err)
	}
	if got := source.binds.Load(); got != 1 {
		t.Fatalf("secret binds = %d, want 1", got)
	}
	if err := BindControlWorkerSecrets(context.Background(), status); err != errStatusAlreadyReported {
		t.Fatalf("second BindControlWorkerSecrets() error = %v, want %v", err, errStatusAlreadyReported)
	}
	if err := ReportControlWorkerReady(status); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
	if err := CloseControlWorkerChild(status); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestBindControlWorkerSecretsFailureNeverEnablesReady(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		source *testChildSource
	}{
		{name: "error", source: &testChildSource{bindErr: errors.New("secret bind failed")}},
		{name: "panic", source: &testChildSource{panicBind: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			status := newChildStatus(writer, test.source)
			status.snapshotBuilt = true
			if err := ReportControlWorkerSecretReady(status); err != nil {
				t.Fatalf("SecretReady() error = %v", err)
			}
			if err := BindControlWorkerSecrets(context.Background(), status); err != errInvalidChildInvocation {
				t.Fatalf("BindControlWorkerSecrets() error = %v, want %v", err, errInvalidChildInvocation)
			}
			if err := ReportControlWorkerReady(status); err != errStatusAlreadyReported {
				t.Fatalf("Ready() after failed binding error = %v, want %v", err, errStatusAlreadyReported)
			}
			if err := CloseControlWorkerChild(status); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			frames, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if string(frames) != "S" {
				t.Fatalf("status frames = %q, want SECRET_READY only", frames)
			}
		})
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
	if err := ReportControlWorkerSecretReady(status); err != nil {
		t.Fatalf("original SecretReady() error = %v", err)
	}
	if err := BindControlWorkerSecrets(context.Background(), status); err != nil {
		t.Fatalf("original BindControlWorkerSecrets() error = %v", err)
	}
	if err := ReportControlWorkerReady(status); err != nil {
		t.Fatalf("original Ready() error = %v", err)
	}
	frame := make([]byte, 2)
	if read, err := io.ReadFull(reader, frame); err != nil || read != 2 || string(frame) != "SR" {
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
		if err := ReportControlWorkerSecretReady(status); err != nil {
			t.Fatalf("iteration %d SecretReady() error = %v", iteration, err)
		}
		if err := BindControlWorkerSecrets(context.Background(), status); err != nil {
			t.Fatalf("iteration %d BindControlWorkerSecrets() error = %v", iteration, err)
		}
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

type testChildSource struct {
	closed    bool
	binds     atomic.Int32
	bindErr   error
	panicBind bool
}

func (source *testChildSource) BindControlWorkerSecrets(context.Context) error {
	source.binds.Add(1)
	if source.panicBind {
		panic("secret bind test panic")
	}
	return source.bindErr
}

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

func (source *countingChildSource) BindControlWorkerSecrets(context.Context) error {
	return nil
}

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

func TestProductionSupervisorSecretSupplierIsInstalled(t *testing.T) {
	settings := defaultSupervisorSettings()
	if settings.supplySecrets == nil {
		t.Fatal("production secret supplier is nil")
	}
}

func contextWithImmediateCancellation() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, cancel
}
