//go:build linux

package workerprocess

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const controlWorkerTestScenario = "AIOPS_WORKERPROCESS_TEST_SCENARIO"
const controlWorkerPdeathParentArgument = "--aiops-workerprocess-test-pdeath-parent"
const controlWorkerRaceOptions = "GORACE=atexit_sleep_ms=0"

func TestMain(testingMain *testing.M) {
	scenario := os.Getenv(controlWorkerTestScenario)
	if scenario != "" {
		// The race runtime otherwise sleeps for one second while the helper exits,
		// which is not part of the supervised process's shutdown behavior. Clear
		// both test-only inputs before the child validates its empty environment.
		_ = os.Unsetenv(controlWorkerTestScenario)
		_ = os.Unsetenv("GORACE")
		switch {
		case len(os.Args) == 2 && os.Args[1] == controlWorkerPdeathParentArgument:
			os.Exit(runPdeathParentTestHelper(scenario))
		case IsControlWorkerSourceLoaderChild(os.Args[1:]):
			os.Exit(runSourceLoaderTestChild(scenario))
		case IsControlWorkerChild(os.Args[1:]):
			os.Exit(runControlWorkerTestChild(scenario))
		}
	}
	os.Exit(testingMain.Run())
}

func TestProductionCommandBoundaryIsFixed(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	settings := defaultSupervisorSettings()
	output := newBoundedDiscard(settings.outputLimit)
	command := buildControlWorkerCommand(settings, output, new(int))
	if command.Path != controlWorkerExecutable {
		t.Fatalf("Path = %q, want fixed executable", command.Path)
	}
	if got, want := command.Args, []string{controlWorkerExecutable, controlWorkerChildArgument}; !equalStrings(got, want) {
		t.Fatalf("Args = %#v, want %#v", got, want)
	}
	if command.Env == nil || len(command.Env) != 0 {
		t.Fatalf("Env = %#v, want non-nil empty environment", command.Env)
	}
	if command.Dir != "/" || command.Stdin != nil {
		t.Fatalf("Dir/Stdin = (%q, %#v), want root/nil", command.Dir, command.Stdin)
	}
	if command.Stdout != output || command.Stderr != output || len(command.ExtraFiles) != 0 {
		t.Fatal("output or pre-handoff descriptor boundary changed")
	}
	if command.WaitDelay != controlWorkerWaitDelay {
		t.Fatalf("WaitDelay = %s, want %s", command.WaitDelay, controlWorkerWaitDelay)
	}
	if command.SysProcAttr == nil || command.SysProcAttr.PidFD == nil {
		t.Fatalf("SysProcAttr = %#v", command.SysProcAttr)
	}
	// Compare the complete structure so Setsid/Foreground/Pgid, clone and
	// unshare flags, credentials and ID mappings, ambient capabilities, cgroup
	// placement, terminal controls, ptrace and chroot all remain at zero values.
	wantSysProcAttr := &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
		PidFD:     command.SysProcAttr.PidFD,
	}
	if !reflect.DeepEqual(command.SysProcAttr, wantSysProcAttr) {
		t.Fatalf("SysProcAttr = %#v, want %#v", command.SysProcAttr, wantSysProcAttr)
	}
}

func TestProductionSourceLoaderCommandBoundaryIsFixed(t *testing.T) {
	pidFD := -1
	command := buildSourceLoaderCommand(&pidFD)
	if command.Path != controlWorkerExecutable ||
		!equalStrings(command.Args, []string{controlWorkerExecutable, controlWorkerLoaderArgument}) {
		t.Fatalf("loader path/args = %q/%q", command.Path, command.Args)
	}
	if command.Env == nil || len(command.Env) != 0 || command.Dir != "/" || command.Stdin != nil ||
		command.Stdout != io.Discard || command.Stderr != io.Discard || len(command.ExtraFiles) != 0 ||
		command.WaitDelay != controlWorkerWaitDelay {
		t.Fatal("loader process boundary changed")
	}
	want := &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: &pidFD}
	if !reflect.DeepEqual(command.SysProcAttr, want) {
		t.Fatalf("loader SysProcAttr = %#v, want %#v", command.SysProcAttr, want)
	}
}

func TestCurrentParentDeathSignalUsesPointerResult(t *testing.T) {
	if _, err := currentParentDeathSignal(); err != nil {
		t.Fatalf("currentParentDeathSignal() error = %v", err)
	}
}

func TestTerminationPreflightDrainsREADYBeforeQueuedFATAL(t *testing.T) {
	events := make(chan childEvent, 2)
	events <- childEventReady
	events <- childEventFatal
	cause, observed := terminationPreflight(events, nil, nil, errChildExit)
	if !observed || cause != errChildFatal {
		t.Fatalf("terminationPreflight(READY,FATAL) = %v, %t; want %v, true",
			cause, observed, errChildFatal)
	}

	readyOnly := make(chan childEvent, 1)
	readyOnly <- childEventReady
	if cause, observed := terminationPreflight(readyOnly, nil, nil, errChildExit); observed || cause != nil {
		t.Fatalf("terminationPreflight(READY) = %v, %t; want nil, false", cause, observed)
	}
}

func TestTerminatedClassificationRequiresStatusMonitorCompletion(t *testing.T) {
	openEvents := make(chan childEvent)
	if cause := classifyTerminatedControlWorker(openEvents, nil); cause != errChildProtocol {
		t.Fatalf("classifyTerminatedControlWorker(open status) = %v, want %v", cause, errChildProtocol)
	}

	closedEvents := make(chan childEvent)
	close(closedEvents)
	if cause := classifyTerminatedControlWorker(closedEvents, nil); cause != nil {
		t.Fatalf("classifyTerminatedControlWorker(closed status) = %v, want nil", cause)
	}

	fatalEvents := make(chan childEvent, 1)
	fatalEvents <- childEventFatal
	close(fatalEvents)
	if cause := classifyTerminatedControlWorker(fatalEvents, nil); cause != errChildFatal {
		t.Fatalf("classifyTerminatedControlWorker(FATAL then close) = %v, want %v", cause, errChildFatal)
	}
}

func TestStatusMonitorClosesOnlyAfterPublishingBufferedFrames(t *testing.T) {
	events := make(chan childEvent, 4)
	go monitorChildStatus(strings.NewReader("RF"), events)
	var observed []childEvent
	for event := range events {
		observed = append(observed, event)
	}
	if len(observed) != 2 || observed[0] != childEventReady || observed[1] != childEventFatal {
		t.Fatalf("monitorChildStatus(RF) events = %#v, want READY,FATAL before close", observed)
	}
}

func TestSupervisorGracefulContextStopUsesTERMAndReaps(t *testing.T) {
	base := filepath.Join(t.TempDir(), "graceful")
	supervisor := newTestSupervisor("ready-exit-on-term", base)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- supervisor.Run(ctx) }()
	waitForMarker(t, base+".ready")
	cancel()
	if err := receiveResult(t, result); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	waitForMarker(t, base+".term")
	assertRecordedPIDGone(t, base+".pid")
}

func TestSupervisorContextStopKillsTermIgnoringGroupAndReaps(t *testing.T) {
	base := filepath.Join(t.TempDir(), "forced")
	supervisor := newTestSupervisor("ready-hold-on-term-with-descendant", base)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- supervisor.Run(ctx) }()
	waitForMarker(t, base+".ready")
	cancel()
	if err := receiveResult(t, result); err != errChildStop {
		t.Fatalf("Run() error = %v, want %v", err, errChildStop)
	}
	waitForMarker(t, base+".term")
	assertRecordedPIDGone(t, base+".pid")
	assertRecordedPIDGone(t, base+".descendant-pid")
}

func TestProcessGroupGoneRejectsLiveMemberAfterLeaderWait(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "member.pid")
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	command := exec.Command(
		"/bin/sh", "-c",
		`trap '' HUP TERM; (trap '' HUP TERM; while :; do sleep 1; done) & printf '%s' "$!" > "$1"; exit 0`,
		"sh", pidPath,
	)
	command.Env = []string{}
	command.Stdin = null
	command.Stdout = null
	command.Stderr = null
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatalf("start process-group leader: %v", err)
	}
	leaderPID := command.Process.Pid
	defer func() { _ = syscall.Kill(-leaderPID, syscall.SIGKILL) }()
	if err := command.Wait(); err != nil {
		t.Fatalf("wait process-group leader: %v", err)
	}
	waitForMarker(t, pidPath)
	memberBytes, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("read process-group member pid: %v", err)
	}
	memberPID, err := strconv.Atoi(string(memberBytes))
	if err != nil {
		t.Fatalf("parse process-group member pid: %v", err)
	}
	if group, err := syscall.Getpgid(memberPID); err != nil || group != leaderPID {
		t.Fatalf("member pgid = %d, %v; want %d", group, err, leaderPID)
	}
	process := &controlWorkerProcess{pid: leaderPID}
	if process.processGroupGone() {
		t.Fatal("processGroupGone reported success while a same-group member survived leader Wait")
	}
	if err := syscall.Kill(-leaderPID, syscall.SIGKILL); err != nil {
		t.Fatalf("kill surviving process group: %v", err)
	}
	waitForProcessGroupGone(t, process)
}

func TestSupervisorTERMNonzeroExitIsNotGracefulSuccess(t *testing.T) {
	base := filepath.Join(t.TempDir(), "nonzero")
	supervisor := newTestSupervisor("ready-nonzero-on-term", base)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- supervisor.Run(ctx) }()
	waitForMarker(t, base+".ready")
	cancel()
	if err := receiveResult(t, result); err != errChildStop {
		t.Fatalf("Run() error = %v, want %v", err, errChildStop)
	}
	waitForMarker(t, base+".term")
	assertRecordedPIDGone(t, base+".pid")
}

func TestSupervisorStartupTimeoutUsesTERMThenKILLAndReaps(t *testing.T) {
	base := filepath.Join(t.TempDir(), "startup")
	supervisor := newTestSupervisor("no-ready-hold-on-term", base)
	err := supervisor.Run(context.Background())
	if err != errChildStop {
		t.Fatalf("Run() error = %v, want %v", err, errChildStop)
	}
	waitForMarker(t, base+".term")
	assertRecordedPIDGone(t, base+".pid")
}

func TestSupervisorContextCancellationDuringStartupStopsCleanly(t *testing.T) {
	base := filepath.Join(t.TempDir(), "startup-cancel")
	supervisor := newTestSupervisor("no-ready-exit-on-term", base)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- supervisor.Run(ctx) }()
	waitForMarker(t, base+".listening")
	cancel()
	if err := receiveResult(t, result); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	waitForMarker(t, base+".term")
	assertRecordedPIDGone(t, base+".pid")
}

func TestSupervisorFatalNeverSendsTERM(t *testing.T) {
	tests := []string{"fatal-and-exit", "fatal-and-hang", "fatal-before-ready-and-hang"}
	for _, scenario := range tests {
		t.Run(scenario, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), scenario)
			err := newTestSupervisor(scenario, base).Run(context.Background())
			fallback := scenario == "fatal-and-exit" && (err == errChildStartup || err == errChildExit)
			if err != errChildFatal && !fallback {
				t.Fatalf("Run() error = %v, want fatal or fixed exit fallback", err)
			}
			assertMarkerAbsent(t, base+".term")
			assertRecordedPIDGone(t, base+".pid")
		})
	}
}

func TestSupervisorStatusAnomaliesNeverSendTERM(t *testing.T) {
	tests := []string{
		"malformed-before-ready",
		"duplicate-ready",
		"extra-after-ready",
		"status-close-after-ready",
	}
	for _, scenario := range tests {
		t.Run(scenario, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), scenario)
			err := newTestSupervisor(scenario, base).Run(context.Background())
			if err != errChildProtocol {
				t.Fatalf("Run() error = %v, want %v", err, errChildProtocol)
			}
			assertMarkerAbsent(t, base+".term")
			assertRecordedPIDGone(t, base+".pid")
		})
	}
}

func TestSupervisorRejectsExitBeforeAndAfterReady(t *testing.T) {
	for _, scenario := range []string{"exit-before-ready", "exit-after-ready"} {
		t.Run(scenario, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), scenario)
			err := newTestSupervisor(scenario, base).Run(context.Background())
			if err != errChildProtocol && err != errChildStartup && err != errChildExit {
				t.Fatalf("Run() error = %v, want fixed startup/protocol/exit rejection", err)
			}
			assertRecordedPIDGone(t, base+".pid")
		})
	}
}

func TestSupervisorBoundsOutputAndContainsWithoutTERM(t *testing.T) {
	base := filepath.Join(t.TempDir(), "output")
	err := newTestSupervisor("output-flood", base).Run(context.Background())
	if err != errOutputLimit {
		t.Fatalf("Run() error = %v, want %v", err, errOutputLimit)
	}
	if strings.Contains(err.Error(), "sensitive-output-canary") || strings.Contains(err.Error(), base) {
		t.Fatalf("Run() leaked child data: %q", err)
	}
	assertMarkerAbsent(t, base+".term")
	assertRecordedPIDGone(t, base+".pid")
}

func TestSupervisorFatalContainmentRaceHundred(t *testing.T) {
	root := t.TempDir()
	for iteration := 0; iteration < 100; iteration++ {
		base := filepath.Join(root, strconv.Itoa(iteration))
		err := newTestSupervisor("fatal-and-exit", base).Run(context.Background())
		if err != errChildFatal && err != errChildStartup && err != errChildExit {
			t.Fatalf("iteration %d: Run() error = %v, want fatal or fixed exit fallback", iteration, err)
		}
		assertRecordedPIDGone(t, base+".pid")
	}
}

func TestSupervisorConcurrentCancelAndFatalExitRaceHundred(t *testing.T) {
	root := t.TempDir()
	for iteration := 0; iteration < 100; iteration++ {
		base := filepath.Join(root, strconv.Itoa(iteration))
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		supervisor := newTestSupervisor("race-fatal-or-term", base)
		go func() { result <- supervisor.Run(ctx) }()
		waitForMarker(t, base+".ready")
		gate := make(chan struct{})
		var racers sync.WaitGroup
		racers.Add(2)
		go func() {
			defer racers.Done()
			<-gate
			cancel()
		}()
		go func() {
			defer racers.Done()
			<-gate
			writeChildMarker(base+".trigger", "fatal")
		}()
		close(gate)
		racers.Wait()
		if err := receiveResult(t, result); err != errChildFatal {
			t.Fatalf("iteration %d: Run() error = %v, want %v", iteration, err, errChildFatal)
		}
		assertRecordedPIDGone(t, base+".pid")
	}
}

func TestSupervisorMonitorsAnomaliesDuringTERMGraceAndContains(t *testing.T) {
	tests := []struct {
		name     string
		scenario string
		want     error
		marker   string
	}{
		{name: "fatal hang", scenario: "term-stop-then-fatal-hang", want: errChildFatal, marker: ".fatal"},
		{name: "fatal immediate exit", scenario: "term-stop-then-fatal-exit", want: errChildFatal, marker: ".fatal"},
		{name: "protocol", scenario: "term-stop-then-protocol-hang", want: errChildProtocol, marker: ".protocol"},
		{name: "output", scenario: "term-stop-then-output-hang", want: errOutputLimit, marker: ".output"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "term-anomaly")
			supervisor := newTestSupervisor(test.scenario, base)
			// Make the ordinary graceful window visibly longer than the anomaly
			// containment window. A parent that stops consuming status after TERM
			// will therefore fail deterministically instead of winning a race.
			supervisor.settings.shutdownGrace = 3 * time.Second
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { result <- supervisor.Run(ctx) }()
			waitForMarker(t, base+".ready")
			cancel()
			waitForMarker(t, base+".stop-entered")
			started := time.Now()
			writeChildMarker(base+".anomaly-trigger", "trigger")
			if err := receiveResult(t, result); err != test.want {
				t.Fatalf("Run() error = %v, want %v", err, test.want)
			}
			if elapsed := time.Since(started); elapsed >= supervisor.settings.shutdownGrace {
				t.Fatalf("anomaly containment took %s, ordinary shutdown grace is %s",
					elapsed, supervisor.settings.shutdownGrace)
			}
			waitForMarker(t, base+test.marker)
			// This marker is auxiliary evidence; the production AST gate locks the
			// sole SIGTERM callsite because standard signals may coalesce.
			assertMarkerValue(t, base+".term-count", "1")
			assertRecordedPIDGone(t, base+".pid")
		})
	}
}

func TestParentDeathSignalKillsAcceptedChild(t *testing.T) {
	base := filepath.Join(t.TempDir(), "pdeath")
	command := exec.Command(controlWorkerExecutable, controlWorkerPdeathParentArgument)
	command.Args = []string{controlWorkerExecutable, controlWorkerPdeathParentArgument}
	command.Env = []string{
		controlWorkerTestScenario + "=pdeath-parent|" + base,
		controlWorkerRaceOptions,
	}
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		t.Fatalf("parent helper error = %v", err)
	}
	waitForMarker(t, base+".ready")
	waitForRecordedPIDGone(t, base+".pid")
}

func TestSourceFailureAfterStartKillsAndReapsEntireProcessGroup(t *testing.T) {
	base := filepath.Join(t.TempDir(), "source-start-failure")
	settings := defaultSupervisorSettings()
	settings.killConfirm = 3 * time.Second
	settings.childEnv = []string{
		controlWorkerTestScenario + "=ready-hold-on-term-with-descendant|" + base,
		controlWorkerRaceOptions,
	}
	source, err := newTestControlWorkerSource()
	if err != nil {
		t.Fatal(err)
	}
	concrete := source.(*testControlWorkerSource)
	concrete.failAfterStart = true
	concrete.afterStart = func() { waitForMarker(t, base+".descendant-pid") }
	process, events, output, err := startControlWorker(settings, concrete)
	if process != nil || events != nil || output != nil || err != errChildStart {
		t.Fatalf("startControlWorker() = (%#v, %#v, %#v, %v), want contained start failure", process, events, output, err)
	}
	assertRecordedPIDGone(t, base+".pid")
	assertRecordedPIDGone(t, base+".descendant-pid")
}

func TestSourceLoaderTimeoutKillsAndReapsEntireProcessGroup(t *testing.T) {
	base := filepath.Join(t.TempDir(), "source-loader-timeout")
	command := exec.Command(controlWorkerExecutable, controlWorkerLoaderArgument)
	command.Args = []string{controlWorkerExecutable, controlWorkerLoaderArgument}
	command.Env = []string{
		controlWorkerTestScenario + "=source-loader-hang|" + base,
		controlWorkerRaceOptions,
	}
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = controlWorkerWaitDelay
	pidFD := -1
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: &pidFD}
	started := time.Now()
	source, err := loadControlWorkerSourceFromCommandUnchecked(context.Background(), 250*time.Millisecond, command)
	if source != nil || err != errChildStart {
		t.Fatalf("loadControlWorkerSourceFromCommand() = (%#v, %v), want contained failure", source, err)
	}
	if elapsed := time.Since(started); elapsed >= sourceLoaderKillConfirmation {
		t.Fatalf("source loader containment took %s", elapsed)
	}
	assertRecordedPIDGone(t, base+".pid")
	assertRecordedPIDGone(t, base+".descendant-pid")
}

func TestInvalidSourceLoaderFrameStillKillsSameGroupDescendant(t *testing.T) {
	base := filepath.Join(t.TempDir(), "source-loader-invalid")
	command := exec.Command(controlWorkerExecutable, controlWorkerLoaderArgument)
	command.Args = []string{controlWorkerExecutable, controlWorkerLoaderArgument}
	command.Env = []string{
		controlWorkerTestScenario + "=source-loader-invalid|" + base,
		controlWorkerRaceOptions,
	}
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = controlWorkerWaitDelay
	pidFD := -1
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: &pidFD}
	source, err := loadControlWorkerSourceFromCommandUnchecked(context.Background(), 3*time.Second, command)
	if source != nil || err != errChildStart {
		t.Fatalf("loadControlWorkerSourceFromCommand() = (%#v, %v), want contained rejection", source, err)
	}
	assertRecordedPIDGone(t, base+".pid")
	assertRecordedPIDGone(t, base+".descendant-pid")
}

func TestUntrustedSourceLoaderPIDFDNeverCallsWait(t *testing.T) {
	pidFD := -1
	command := exec.Command("/bin/sh", "-c", "trap '' TERM; while :; do sleep 1; done")
	command.Env = []string{}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = controlWorkerWaitDelay
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: &pidFD}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exitDone := make(chan struct{})
	close(exitDone)
	var exitTrusted atomic.Bool
	contained, err := finalizeSourceLoader(
		command, nil, pidFD, exitDone, &exitTrusted, true, sourceLoaderKillConfirmation,
	)
	if contained || err != errChildStart {
		t.Fatalf("finalizeSourceLoader() = %t, %v; want untrusted fail-stop", contained, err)
	}
	// The fail-stop path returns without synchronously waiting. Its sole
	// background reaper owns Wait; the process was already group-killed.
}

func TestSourceLoaderStartRejectsPostBuildCommandDrift(t *testing.T) {
	for name, mutate := range map[string]func(*exec.Cmd){
		"path":          func(command *exec.Cmd) { command.Path = "/tmp/not-worker" },
		"argument":      func(command *exec.Cmd) { command.Args[1] = "--other" },
		"environment":   func(command *exec.Cmd) { command.Env = []string{"A=B"} },
		"directory":     func(command *exec.Cmd) { command.Dir = "/tmp" },
		"stdin":         func(command *exec.Cmd) { command.Stdin = bytes.NewReader(nil) },
		"stdout":        func(command *exec.Cmd) { command.Stdout = &bytes.Buffer{} },
		"wait delay":    func(command *exec.Cmd) { command.WaitDelay++ },
		"process group": func(command *exec.Cmd) { command.SysProcAttr.Setpgid = false },
		"death signal":  func(command *exec.Cmd) { command.SysProcAttr.Pdeathsig = 0 },
		"missing pidfd": func(command *exec.Cmd) { command.SysProcAttr.PidFD = nil },
	} {
		t.Run(name, func(t *testing.T) {
			pidFD := -1
			command := buildSourceLoaderCommand(&pidFD)
			mutate(command)
			source, err := loadControlWorkerSourceFromCommand(context.Background(), time.Second, command)
			if source != nil || err != errChildStart || command.Process != nil {
				t.Fatalf("drifted loader start = (%#v, %v, process %#v)", source, err, command.Process)
			}
		})
	}
}

func TestCancellationAfterSourceLoadDoesNotStartControlChild(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source, err := newTestControlWorkerSource()
	if err != nil {
		t.Fatal(err)
	}
	concrete := source.(*testControlWorkerSource)
	settings := defaultSupervisorSettings()
	settings.openSource = func(context.Context, time.Duration) (controlWorkerSource, error) {
		cancel()
		return concrete, nil
	}
	if err := runControlWorkerSupervisor(ctx, settings); err != errChildStart {
		t.Fatalf("runControlWorkerSupervisor() error = %v, want %v", err, errChildStart)
	}
	concrete.mu.Lock()
	starts, closed := concrete.starts, concrete.closed
	concrete.mu.Unlock()
	if starts != 0 || !closed {
		t.Fatalf("cancelled source lifecycle = starts %d, closed %t", starts, closed)
	}
}

func TestBoundedDiscardSignalsOnceAndNeverRetainsOutput(t *testing.T) {
	writer := newBoundedDiscard(4)
	if written, err := writer.Write([]byte("1234")); written != 4 || err != nil {
		t.Fatalf("first Write() = (%d, %v)", written, err)
	}
	if written, err := writer.Write([]byte("5")); written != 0 || err != errOutputLimit {
		t.Fatalf("overflow Write() = (%d, %v)", written, err)
	}
	select {
	case <-writer.exceeded:
	default:
		t.Fatal("output limit signal was not closed")
	}
	if written, err := writer.Write([]byte("6")); written != 0 || err != errOutputLimit {
		t.Fatalf("repeated overflow Write() = (%d, %v)", written, err)
	}
}

func TestAcceptControlWorkerChildRejectsBoundaryDrift(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*exec.Cmd, *os.File, string)
	}{
		{name: "missing status fd", configure: func(command *exec.Cmd, _ *os.File, _ string) {
			command.ExtraFiles = nil
		}},
		{name: "read-only status fd", configure: func(command *exec.Cmd, _ *os.File, _ string) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			command.ExtraFiles = []*os.File{reader}
			t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
		}},
		{name: "missing source fd", configure: func(command *exec.Cmd, _ *os.File, _ string) {
			command.ExtraFiles = command.ExtraFiles[:1]
		}},
		{name: "swapped status and source", configure: func(command *exec.Cmd, _ *os.File, _ string) {
			command.ExtraFiles[0], command.ExtraFiles[1] = command.ExtraFiles[1], command.ExtraFiles[0]
		}},
		{name: "extra inherited descriptor", configure: func(command *exec.Cmd, _ *os.File, _ string) {
			extra, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			command.ExtraFiles = append(command.ExtraFiles, extra)
			t.Cleanup(func() { _ = extra.Close() })
		}},
		{name: "non-empty environment", configure: func(command *exec.Cmd, _ *os.File, _ string) {
			command.Env = append(command.Env, "UNEXPECTED=value")
		}},
		{name: "wrong cwd", configure: func(command *exec.Cmd, _ *os.File, directory string) {
			command.Dir = directory
		}},
		{name: "shared process group", configure: func(command *exec.Cmd, _ *os.File, _ string) {
			command.SysProcAttr.Setpgid = false
		}},
		{name: "missing parent death signal", configure: func(command *exec.Cmd, _ *os.File, _ string) {
			command.SysProcAttr.Pdeathsig = 0
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			command := acceptBoundaryCommand(t, "accept-reject", writer)
			test.configure(command, writer, directory)
			if err := command.Run(); err != nil {
				t.Fatalf("boundary rejection helper failed: %v", err)
			}
		})
	}
}

func TestAcceptControlWorkerChildAcceptsExactBoundary(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if err := acceptBoundaryCommand(t, "accept-exact", writer).Run(); err != nil {
		t.Fatalf("exact boundary helper failed: %v", err)
	}
}

func newTestSupervisor(scenario, base string) *ControlWorkerSupervisor {
	settings := defaultSupervisorSettings()
	settings.startupTimeout = 300 * time.Millisecond
	settings.startupGrace = time.Second
	settings.shutdownGrace = time.Second
	settings.anomalyGrace = 250 * time.Millisecond
	settings.killConfirm = 3 * time.Second
	settings.childEnv = []string{
		controlWorkerTestScenario + "=" + scenario + "|" + base,
		controlWorkerRaceOptions,
	}
	settings.openSource = func(context.Context, time.Duration) (controlWorkerSource, error) {
		return newTestControlWorkerSource()
	}
	return newControlWorkerSupervisor(settings)
}

const testControlWorkerSourceContents = "aiops-workerprocess-test-source-v1"

type testControlWorkerSource struct {
	mu             sync.Mutex
	file           *os.File
	closed         bool
	starts         int
	afterStart     func()
	failAfterStart bool
}

func newTestControlWorkerSource() (controlWorkerSource, error) {
	file, err := os.CreateTemp("", "aiops-workerprocess-source")
	if err != nil {
		return nil, err
	}
	_ = os.Remove(file.Name())
	if _, err := file.WriteString(testControlWorkerSourceContents); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &testControlWorkerSource{file: file}, nil
}

func (source *testControlWorkerSource) StartChild(command *exec.Cmd, status *os.File) error {
	if source == nil || command == nil || status == nil {
		return errChildStart
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed || source.file == nil {
		return errChildStart
	}
	source.starts++
	command.ExtraFiles = []*os.File{status, source.file}
	defer func() { command.ExtraFiles = nil }()
	err := command.Start()
	if err == nil && source.afterStart != nil {
		source.afterStart()
	}
	closeErr := source.file.Close()
	source.file = nil
	source.closed = true
	if err != nil || closeErr != nil || source.failAfterStart {
		return errChildStart
	}
	return nil
}

func (source *testControlWorkerSource) Close() error {
	if source == nil {
		return errChildStart
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed {
		return nil
	}
	source.closed = true
	if source.file == nil {
		return errChildStart
	}
	err := source.file.Close()
	source.file = nil
	return err
}

func newTestSourceFile(t *testing.T) *os.File {
	t.Helper()
	source, err := newTestControlWorkerSource()
	if err != nil {
		t.Fatal(err)
	}
	concrete := source.(*testControlWorkerSource)
	file := concrete.file
	t.Cleanup(func() { _ = concrete.Close() })
	return file
}

func acceptTestInheritedControlWorkerSource() (io.Closer, error) {
	fd := inheritedTestSourceFD()
	if fd < 0 {
		return nil, errInvalidChildInvocation
	}
	unix.CloseOnExec(fd)
	contents := make([]byte, len(testControlWorkerSourceContents))
	read, err := unix.Pread(fd, contents, 0)
	if err != nil || read != len(contents) || string(contents) != testControlWorkerSourceContents {
		return nil, errInvalidChildInvocation
	}
	file := os.NewFile(uintptr(fd), "control-worker-test-source")
	if file == nil {
		return nil, errInvalidChildInvocation
	}
	return file, nil
}

func inheritedTestSourceFD() int {
	fd := 4
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return -1
	}
	return fd
}

func acceptBoundaryCommand(t *testing.T, scenario string, statusFile *os.File) *exec.Cmd {
	t.Helper()
	sourceFile := newTestSourceFile(t)
	command := exec.Command(controlWorkerExecutable, controlWorkerChildArgument)
	command.Args = []string{controlWorkerExecutable, controlWorkerChildArgument}
	command.Env = []string{
		controlWorkerTestScenario + "=" + scenario + "|",
		controlWorkerRaceOptions,
	}
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = []*os.File{statusFile, sourceFile}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	return command
}

func runControlWorkerTestChild(raw string) int {
	parts := strings.SplitN(raw, "|", 2)
	scenario := parts[0]
	base := ""
	if len(parts) == 2 {
		base = parts[1]
	}
	status, err := acceptControlWorkerChildWithSource(acceptTestInheritedControlWorkerSource)
	if scenario == "accept-reject" {
		if err != nil && status == nil {
			return 0
		}
		return 91
	}
	if scenario == "accept-exact" {
		if err != nil || status == nil {
			return 92
		}
		descriptorFlags, descriptorErr := unix.FcntlInt(controlWorkerStatusFD, unix.F_GETFD, 0)
		if descriptorErr != nil || descriptorFlags&unix.FD_CLOEXEC == 0 {
			return 93
		}
		if CloseControlWorkerChild(status) != nil {
			return 94
		}
		return 0
	}
	if err != nil || status == nil {
		return 90
	}
	writeChildMarker(base+".pid", strconv.Itoa(os.Getpid()))
	switch scenario {
	case "ready-exit-on-term":
		signals := captureTestTERM()
		if ReportControlWorkerReady(status) != nil {
			return 80
		}
		writeChildMarker(base+".ready", "ready")
		waitForTestTERM(status, base, true, signals)
		return 0
	case "ready-nonzero-on-term":
		signals := captureTestTERM()
		if ReportControlWorkerReady(status) != nil {
			return 97
		}
		writeChildMarker(base+".ready", "ready")
		waitForTestTERM(status, base, true, signals)
		return 17
	case "ready-hold-on-term-with-descendant":
		signals := captureTestTERM()
		descendant := exec.Command("/bin/sh", "-c", "trap '' TERM; while :; do sleep 1; done")
		descendant.Env = []string{}
		if descendant.Start() != nil {
			return 81
		}
		writeChildMarker(base+".descendant-pid", strconv.Itoa(descendant.Process.Pid))
		if ReportControlWorkerReady(status) != nil {
			return 82
		}
		writeChildMarker(base+".ready", "ready")
		waitForTestTERM(status, base, false, signals)
		return 83
	case "no-ready-hold-on-term":
		signals := captureTestTERM()
		writeChildMarker(base+".listening", "listening")
		waitForTestTERM(status, base, false, signals)
		return 84
	case "no-ready-exit-on-term":
		signals := captureTestTERM()
		writeChildMarker(base+".listening", "listening")
		waitForTestTERM(status, base, true, signals)
		return 0
	case "fatal-and-exit":
		if ReportControlWorkerReady(status) != nil {
			return 85
		}
		ExitControlWorkerFatal(status)
	case "fatal-and-hang":
		signals := captureTestTERM()
		if ReportControlWorkerReady(status) != nil || writeStatusByte(status.file, controlWorkerFatalByte) != nil {
			return 86
		}
		waitForTestTERM(status, base, false, signals)
	case "fatal-before-ready-and-hang":
		signals := captureTestTERM()
		if writeStatusByte(status.file, controlWorkerFatalByte) != nil {
			return 87
		}
		waitForTestTERM(status, base, false, signals)
	case "malformed-before-ready":
		signals := captureTestTERM()
		_, _ = status.file.Write([]byte{'X'})
		waitForTestTERM(status, base, false, signals)
	case "duplicate-ready":
		signals := captureTestTERM()
		_, _ = status.file.Write([]byte{'R', 'R'})
		waitForTestTERM(status, base, false, signals)
	case "extra-after-ready":
		signals := captureTestTERM()
		_, _ = status.file.Write([]byte{'R', 'X'})
		waitForTestTERM(status, base, false, signals)
	case "status-close-after-ready":
		signals := captureTestTERM()
		if ReportControlWorkerReady(status) != nil || CloseControlWorkerChild(status) != nil {
			return 88
		}
		waitForTestTERM(status, base, false, signals)
	case "exit-before-ready":
		_ = CloseControlWorkerChild(status)
		return 0
	case "exit-after-ready":
		if ReportControlWorkerReady(status) != nil {
			return 89
		}
		_ = CloseControlWorkerChild(status)
		return 0
	case "output-flood":
		signals := captureTestTERM()
		if ReportControlWorkerReady(status) != nil {
			return 94
		}
		writeChildMarker(base+".ready", "ready")
		_, _ = fmt.Fprint(os.Stderr, "sensitive-output-canary")
		_, _ = fmt.Fprint(os.Stdout, strings.Repeat("x", defaultOutputByteLimit+1))
		waitForTestTERM(status, base, false, signals)
	case "race-fatal-or-term":
		signals := captureTestTERM()
		if ReportControlWorkerReady(status) != nil {
			return 98
		}
		writeChildMarker(base+".ready", "ready")
		for {
			select {
			case <-signals:
				writeChildMarker(base+".term", "term")
				if waitForChildMarker(base+".trigger", time.Second) {
					ExitControlWorkerFatal(status)
				}
				_ = CloseControlWorkerChild(status)
				return 0
			default:
			}
			if _, err := os.Stat(base + ".trigger"); err == nil {
				ExitControlWorkerFatal(status)
			}
			time.Sleep(time.Millisecond)
		}
	case "term-stop-then-fatal-hang", "term-stop-then-fatal-exit",
		"term-stop-then-protocol-hang", "term-stop-then-output-hang":
		return runTermAnomalyTestChild(scenario, status, base)
	case "pdeath-leaf":
		if ReportControlWorkerReady(status) != nil {
			return 99
		}
		writeChildMarker(base+".ready", "ready")
		select {}
	default:
		return 95
	}
	return 96
}

func runPdeathParentTestHelper(raw string) int {
	parts := strings.SplitN(raw, "|", 2)
	if len(parts) != 2 || parts[0] != "pdeath-parent" {
		return 100
	}
	base := parts[1]
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		return 101
	}
	source, err := newTestControlWorkerSource()
	if err != nil {
		_ = statusReader.Close()
		_ = statusWriter.Close()
		return 104
	}
	concreteSource := source.(*testControlWorkerSource)
	command := exec.Command(controlWorkerExecutable, controlWorkerChildArgument)
	command.Args = []string{controlWorkerExecutable, controlWorkerChildArgument}
	command.Env = []string{
		controlWorkerTestScenario + "=pdeath-leaf|" + base,
		controlWorkerRaceOptions,
	}
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = []*os.File{statusWriter, concreteSource.file}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		_ = source.Close()
		return 102
	}
	_ = source.Close()
	_ = statusWriter.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(base + ".ready"); err == nil {
			_ = statusReader
			return 0
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 103
}

func runSourceLoaderTestChild(raw string) int {
	parts := strings.SplitN(raw, "|", 2)
	if len(parts) != 2 || (parts[0] != "source-loader-hang" && parts[0] != "source-loader-invalid") {
		return 105
	}
	base := parts[1]
	writeChildMarker(base+".pid", strconv.Itoa(os.Getpid()))
	descendant := exec.Command("/bin/sh", "-c", "trap '' TERM; while :; do sleep 1; done")
	descendant.Env = []string{}
	if descendant.Start() != nil {
		return 106
	}
	writeChildMarker(base+".descendant-pid", strconv.Itoa(descendant.Process.Pid))
	if parts[0] == "source-loader-invalid" {
		writer := os.NewFile(controlWorkerStatusFD, "source-loader-invalid")
		if writer == nil {
			return 107
		}
		_, _ = writer.Write([]byte("invalid-public-source-frame"))
		_ = writer.Close()
		return 0
	}
	select {}
}

func captureTestTERM() chan os.Signal {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	return signals
}

func waitForTestTERM(status *ChildStatus, base string, exit bool, signals <-chan os.Signal) {
	for {
		<-signals
		writeChildMarker(base+".term", "term")
		if exit {
			_ = CloseControlWorkerChild(status)
			return
		}
	}
}

func recordTestTERMs(signals <-chan os.Signal, base string, first chan<- struct{}) {
	count := 0
	for range signals {
		count++
		writeChildMarker(base+".term-count", strconv.Itoa(count))
		if count == 1 {
			close(first)
		}
	}
}

func runTermAnomalyTestChild(scenario string, status *ChildStatus, base string) int {
	signals := captureTestTERM()
	termSeen := make(chan struct{})
	go recordTestTERMs(signals, base, termSeen)
	go func() {
		if !waitForChildMarker(base+".anomaly-trigger", 5*time.Second) {
			return
		}
		switch scenario {
		case "term-stop-then-fatal-hang":
			if writeStatusByte(status.file, controlWorkerFatalByte) == nil {
				writeChildMarker(base+".fatal", "fatal")
			}
			select {}
		case "term-stop-then-fatal-exit":
			writeChildMarker(base+".fatal", "fatal")
			ExitControlWorkerFatal(status)
		case "term-stop-then-protocol-hang":
			_, _ = status.file.Write([]byte{'X'})
			writeChildMarker(base+".protocol", "protocol")
			select {}
		case "term-stop-then-output-hang":
			_, _ = fmt.Fprint(os.Stdout, strings.Repeat("x", defaultOutputByteLimit+1))
			writeChildMarker(base+".output", "output")
			select {}
		}
	}()
	if ReportControlWorkerReady(status) != nil {
		return 104
	}
	writeChildMarker(base+".ready", "ready")
	<-termSeen
	writeChildMarker(base+".stop-entered", "stop")
	select {}
}

func writeChildMarker(path, value string) {
	if path != "" {
		_ = os.WriteFile(path, []byte(value), 0o600)
	}
}

func waitForChildMarker(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func waitForMarker(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("marker %q was not created", path)
}

func assertMarkerAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected TERM marker %q: %v", path, err)
	}
}

func assertMarkerValue(t *testing.T, path, want string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read marker %q: %v", path, err)
	}
	if got := string(contents); got != want {
		t.Fatalf("marker %q = %q, want %q", path, got, want)
	}
}

func assertRecordedPIDGone(t *testing.T, path string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pid marker: %v", err)
	}
	pid, err := strconv.Atoi(string(contents))
	if err != nil {
		t.Fatalf("parse pid marker: %v", err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("pid %d still exists: %v", pid, err)
	}
}

func waitForRecordedPIDGone(t *testing.T, path string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pid marker: %v", err)
	}
	pid, err := strconv.Atoi(string(contents))
	if err != nil {
		t.Fatalf("parse pid marker: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d survived its parent", pid)
}

func waitForProcessGroupGone(t *testing.T, process *controlWorkerProcess) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if process.processGroupGone() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process group %d still exists", process.pid)
}

func receiveResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(12 * time.Second):
		t.Fatal("supervisor did not return")
		return nil
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
