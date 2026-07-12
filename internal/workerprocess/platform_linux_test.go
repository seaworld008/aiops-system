//go:build linux

package workerprocess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const controlWorkerTestScenario = "AIOPS_WORKERPROCESS_TEST_SCENARIO"
const controlWorkerPdeathParentArgument = "--aiops-workerprocess-test-pdeath-parent"

func TestMain(testingMain *testing.M) {
	scenario := os.Getenv(controlWorkerTestScenario)
	if scenario != "" {
		switch {
		case len(os.Args) == 2 && os.Args[1] == controlWorkerPdeathParentArgument:
			_ = os.Unsetenv(controlWorkerTestScenario)
			os.Exit(runPdeathParentTestHelper(scenario))
		case IsControlWorkerChild(os.Args[1:]):
			_ = os.Unsetenv(controlWorkerTestScenario)
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
	command := buildControlWorkerCommand(settings, writer, output, new(int))
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
	if command.Stdout != output || command.Stderr != output ||
		len(command.ExtraFiles) != 1 || command.ExtraFiles[0] != writer {
		t.Fatal("output or anonymous status descriptor boundary changed")
	}
	if command.WaitDelay != controlWorkerWaitDelay {
		t.Fatalf("WaitDelay = %s, want %s", command.WaitDelay, controlWorkerWaitDelay)
	}
	if command.SysProcAttr == nil || !command.SysProcAttr.Setpgid ||
		command.SysProcAttr.Pdeathsig != syscall.SIGKILL || command.SysProcAttr.PidFD == nil {
		t.Fatalf("SysProcAttr = %#v", command.SysProcAttr)
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
		err := receiveResult(t, result)
		if err != nil && err != errChildFatal && err != errChildStop && err != errChildExit {
			t.Fatalf("iteration %d: Run() error = %v", iteration, err)
		}
		assertRecordedPIDGone(t, base+".pid")
	}
}

func TestParentDeathSignalKillsAcceptedChild(t *testing.T) {
	base := filepath.Join(t.TempDir(), "pdeath")
	command := exec.Command(controlWorkerExecutable, controlWorkerPdeathParentArgument)
	command.Args = []string{controlWorkerExecutable, controlWorkerPdeathParentArgument}
	command.Env = []string{controlWorkerTestScenario + "=pdeath-parent|" + base}
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
			command := acceptBoundaryCommand("accept-reject", writer)
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
	if err := acceptBoundaryCommand("accept-exact", writer).Run(); err != nil {
		t.Fatalf("exact boundary helper failed: %v", err)
	}
}

func newTestSupervisor(scenario, base string) *ControlWorkerSupervisor {
	settings := defaultSupervisorSettings()
	settings.startupTimeout = 300 * time.Millisecond
	settings.startupGrace = 120 * time.Millisecond
	settings.shutdownGrace = 120 * time.Millisecond
	settings.anomalyGrace = 120 * time.Millisecond
	settings.killConfirm = 3 * time.Second
	settings.childEnv = []string{controlWorkerTestScenario + "=" + scenario + "|" + base}
	return newControlWorkerSupervisor(settings)
}

func acceptBoundaryCommand(scenario string, statusFile *os.File) *exec.Cmd {
	command := exec.Command(controlWorkerExecutable, controlWorkerChildArgument)
	command.Args = []string{controlWorkerExecutable, controlWorkerChildArgument}
	command.Env = []string{controlWorkerTestScenario + "=" + scenario + "|"}
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = []*os.File{statusFile}
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
	status, err := AcceptControlWorkerChild(os.Args[1:])
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
				_ = CloseControlWorkerChild(status)
				return 0
			default:
			}
			if _, err := os.Stat(base + ".trigger"); err == nil {
				ExitControlWorkerFatal(status)
			}
			time.Sleep(time.Millisecond)
		}
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
	command := exec.Command(controlWorkerExecutable, controlWorkerChildArgument)
	command.Args = []string{controlWorkerExecutable, controlWorkerChildArgument}
	command.Env = []string{controlWorkerTestScenario + "=pdeath-leaf|" + base}
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = []*os.File{statusWriter}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		return 102
	}
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

func writeChildMarker(path, value string) {
	if path != "" {
		_ = os.WriteFile(path, []byte(value), 0o600)
	}
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
	case <-time.After(8 * time.Second):
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
