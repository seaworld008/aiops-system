//go:build linux

package workerprocess

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const controlWorkerExecutable = "/proc/self/exe"

type childEvent uint8

const (
	childEventReady childEvent = iota + 1
	childEventFatal
	childEventProtocol
	childEventStatusClosed
)

type controlWorkerProcess struct {
	command      *exec.Cmd
	pid          int
	pidFD        int
	statusReader *os.File
	exitDone     chan struct{}
	exitTrusted  atomic.Bool
	reapDone     chan struct{}
	reapOnce     sync.Once
	waitErr      error
	closeOnce    sync.Once
}

type boundedDiscard struct {
	mu        sync.Mutex
	remaining int64
	exceeded  chan struct{}
	once      sync.Once
}

func newBoundedDiscard(limit int64) *boundedDiscard {
	return &boundedDiscard{remaining: limit, exceeded: make(chan struct{})}
}

func (writer *boundedDiscard) Write(value []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if int64(len(value)) > writer.remaining {
		writer.remaining = 0
		writer.once.Do(func() { close(writer.exceeded) })
		return 0, errOutputLimit
	}
	writer.remaining -= int64(len(value))
	return len(value), nil
}

func acceptControlWorkerChild() (*ChildStatus, error) {
	if len(os.Environ()) != 0 {
		return nil, errInvalidChildInvocation
	}
	workingDirectory, err := os.Getwd()
	if err != nil || workingDirectory != "/" {
		return nil, errInvalidChildInvocation
	}
	pid := os.Getpid()
	group, err := syscall.Getpgid(0)
	// The supervisor is commonly PID 1 inside a container, so a legitimate
	// self-reexec child can have PPID 1. Pdeathsig plus the inherited status
	// capability provide the parent-liveness boundary; rejecting PPID 1 would
	// make the production container permanently fail closed.
	if err != nil || pid <= 1 || group != pid || os.Getppid() <= 0 {
		return nil, errInvalidChildInvocation
	}
	deathSignal, err := currentParentDeathSignal()
	if err != nil || deathSignal != syscall.SIGKILL {
		return nil, errInvalidChildInvocation
	}
	descriptor := int(controlWorkerStatusFD)
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO {
		return nil, errInvalidStatusChannel
	}
	flags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_WRONLY {
		return nil, errInvalidStatusChannel
	}
	unix.CloseOnExec(descriptor)
	descriptorFlags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0)
	if err != nil || descriptorFlags&unix.FD_CLOEXEC == 0 {
		return nil, errInvalidStatusChannel
	}
	file := os.NewFile(controlWorkerStatusFD, "control-worker-status")
	if file == nil {
		return nil, errInvalidStatusChannel
	}
	return newChildStatus(file), nil
}

func currentParentDeathSignal() (syscall.Signal, error) {
	// PR_GET_PDEATHSIG returns zero from prctl and writes the signal through an
	// int pointer. PrctlRetInt is therefore incorrect for this option and would
	// turn every valid Linux child into EFAULT.
	var signal int32
	_, _, errno := syscall.Syscall6(
		unix.SYS_PRCTL,
		uintptr(unix.PR_GET_PDEATHSIG),
		uintptr(unsafe.Pointer(&signal)),
		0,
		0,
		0,
		0,
	)
	runtime.KeepAlive(&signal)
	if errno != 0 {
		return 0, errno
	}
	return syscall.Signal(signal), nil
}

func runControlWorkerSupervisor(ctx context.Context, settings supervisorSettings) error {
	process, events, outputExceeded, err := startControlWorker(settings)
	if err != nil {
		return errChildStart
	}
	startup := time.NewTimer(settings.startupTimeout)
	defer startup.Stop()
	for {
		select {
		case event := <-events:
			switch event {
			case childEventReady:
				return superviseReadyControlWorker(ctx, settings, process, events, outputExceeded)
			case childEventFatal:
				return rejectAfterContainment(process, settings, errChildFatal)
			default:
				return rejectAfterContainment(process, settings, errChildProtocol)
			}
		case <-outputExceeded:
			return rejectAfterContainment(process, settings, errOutputLimit)
		case <-process.exitDone:
			cause := classifyExitedControlWorker(events, outputExceeded, errChildStartup)
			return rejectAfterContainment(process, settings, cause)
		case <-startup.C:
			if !terminateAfterTerm(process, settings.startupGrace, settings.killConfirm) {
				return errChildStop
			}
			return errChildStartup
		case <-ctx.Done():
			if !terminateAfterTerm(process, settings.startupGrace, settings.killConfirm) {
				return errChildStop
			}
			return nil
		}
	}
}

func superviseReadyControlWorker(
	ctx context.Context,
	settings supervisorSettings,
	process *controlWorkerProcess,
	events <-chan childEvent,
	outputExceeded <-chan struct{},
) error {
	for {
		select {
		case event := <-events:
			if event == childEventFatal {
				return rejectAfterContainment(process, settings, errChildFatal)
			}
			return rejectAfterContainment(process, settings, errChildProtocol)
		case <-outputExceeded:
			return rejectAfterContainment(process, settings, errOutputLimit)
		case <-process.exitDone:
			cause := classifyExitedControlWorker(events, outputExceeded, errChildExit)
			return rejectAfterContainment(process, settings, cause)
		case <-ctx.Done():
			// Give already-observed fatal/protocol/output/exit events priority over
			// the graceful path so they can never cause a TERM callback re-entry.
			select {
			case event := <-events:
				if event == childEventFatal {
					return rejectAfterContainment(process, settings, errChildFatal)
				}
				return rejectAfterContainment(process, settings, errChildProtocol)
			case <-outputExceeded:
				return rejectAfterContainment(process, settings, errOutputLimit)
			case <-process.exitDone:
				cause := classifyExitedControlWorker(events, outputExceeded, errChildExit)
				return rejectAfterContainment(process, settings, cause)
			default:
			}
			if !terminateAfterTerm(process, settings.shutdownGrace, settings.killConfirm) {
				return errChildStop
			}
			return nil
		}
	}
}

func startControlWorker(settings supervisorSettings) (*controlWorkerProcess, <-chan childEvent, <-chan struct{}, error) {
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, errChildStart
	}
	output := newBoundedDiscard(settings.outputLimit)
	pidFD := -1
	command := buildControlWorkerCommand(settings, statusWriter, output, &pidFD)
	if err := command.Start(); err != nil {
		_ = statusReader.Close()
		_ = statusWriter.Close()
		return nil, nil, nil, errChildStart
	}
	_ = statusWriter.Close()
	if pidFD < 0 {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = statusReader.Close()
		return nil, nil, nil, errChildStart
	}
	process := &controlWorkerProcess{
		command:      command,
		pid:          command.Process.Pid,
		pidFD:        pidFD,
		statusReader: statusReader,
		exitDone:     make(chan struct{}),
		reapDone:     make(chan struct{}),
	}
	go func() {
		process.exitTrusted.Store(waitPIDFD(pidFD) == nil)
		close(process.exitDone)
	}()
	events := make(chan childEvent, 4)
	go monitorChildStatus(statusReader, events)
	return process, events, output.exceeded, nil
}

func buildControlWorkerCommand(
	settings supervisorSettings,
	statusWriter *os.File,
	output io.Writer,
	pidFD *int,
) *exec.Cmd {
	command := exec.Command(controlWorkerExecutable, controlWorkerChildArgument)
	command.Args = []string{controlWorkerExecutable, controlWorkerChildArgument}
	command.Env = append([]string{}, settings.childEnv...)
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = output
	command.Stderr = output
	command.ExtraFiles = []*os.File{statusWriter}
	command.WaitDelay = controlWorkerWaitDelay
	command.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
		PidFD:     pidFD,
	}
	return command
}

func classifyExitedControlWorker(
	events <-chan childEvent,
	outputExceeded <-chan struct{},
	fallback error,
) error {
	timer := time.NewTimer(exitClassificationGrace)
	defer timer.Stop()
	cause := fallback
	for {
		select {
		case event := <-events:
			switch event {
			case childEventFatal:
				return errChildFatal
			case childEventReady:
				continue
			default:
				cause = errChildProtocol
			}
		case <-outputExceeded:
			return errOutputLimit
		case <-timer.C:
			return cause
		}
	}
}

func monitorChildStatus(reader io.Reader, events chan<- childEvent) {
	state := childStatusOpen
	buffer := make([]byte, 32)
	for {
		read, err := reader.Read(buffer)
		for _, value := range buffer[:read] {
			switch {
			case state == childStatusOpen && value == controlWorkerReadyByte:
				state = childStatusReady
				events <- childEventReady
			case (state == childStatusOpen || state == childStatusReady) && value == controlWorkerFatalByte:
				state = childStatusClosed
				events <- childEventFatal
			default:
				state = childStatusClosed
				events <- childEventProtocol
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) || state != childStatusClosed {
				events <- childEventStatusClosed
			}
			return
		}
		if read == 0 {
			events <- childEventProtocol
			return
		}
	}
}

func terminateAfterTerm(process *controlWorkerProcess, grace, killConfirm time.Duration) bool {
	if process == nil {
		return false
	}
	termOK := process.signalGroup(syscall.SIGTERM)
	if process.waitForContained(grace) {
		reaped, clean := process.reapWithin(killConfirm)
		return termOK && reaped && clean && process.processGroupGone()
	}
	killOK := process.signalGroup(syscall.SIGKILL)
	if !killOK && process.command != nil && process.command.Process != nil {
		_ = process.command.Process.Kill()
	}
	_ = process.waitForContained(killConfirm)
	_, _ = process.reapWithin(killConfirm)
	return false
}

func rejectAfterContainment(process *controlWorkerProcess, settings supervisorSettings, cause error) error {
	if !containWithoutTerm(process, settings.anomalyGrace, settings.killConfirm) {
		return errChildStop
	}
	return cause
}

func containWithoutTerm(process *controlWorkerProcess, grace, killConfirm time.Duration) bool {
	if process == nil {
		return false
	}
	contained := process.waitForContained(grace)
	killOK := true
	if !contained {
		killOK = process.signalGroup(syscall.SIGKILL)
		if !killOK && process.command != nil && process.command.Process != nil {
			killOK = process.command.Process.Kill() == nil || process.exited()
		}
		contained = process.waitForContained(killConfirm)
	}
	reaped, _ := process.reapWithin(killConfirm)
	return killOK && contained && reaped && process.processGroupGone()
}

func (process *controlWorkerProcess) exited() bool {
	if process == nil {
		return false
	}
	select {
	case <-process.exitDone:
		return true
	default:
		return false
	}
}

func (process *controlWorkerProcess) waitForContained(timeout time.Duration) bool {
	if process == nil {
		return false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-process.exitDone:
		if !process.exitTrusted.Load() {
			return false
		}
	case <-timer.C:
		return false
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		members, trusted := process.groupHasOtherMembers()
		if trusted && !members {
			return true
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			return false
		}
	}
}

func (process *controlWorkerProcess) groupHasOtherMembers() (bool, bool) {
	if process == nil || process.pid <= 1 {
		return false, false
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, false
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == process.pid {
			continue
		}
		contents, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, false
		}
		end := strings.LastIndexByte(string(contents), ')')
		if end < 0 || end+2 > len(contents) {
			return false, false
		}
		fields := strings.Fields(string(contents[end+2:]))
		if len(fields) < 3 {
			return false, false
		}
		group, err := strconv.Atoi(fields[2])
		if err != nil {
			return false, false
		}
		if group == process.pid {
			return true, true
		}
	}
	return false, true
}

func (process *controlWorkerProcess) reapWithin(timeout time.Duration) (bool, bool) {
	if process == nil {
		return false, false
	}
	process.reapOnce.Do(func() {
		go func() {
			process.waitErr = process.command.Wait()
			_ = unix.Close(process.pidFD)
			process.closeStatus()
			close(process.reapDone)
		}()
	})
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-process.reapDone:
		return process.exitTrusted.Load(), process.waitErr == nil
	case <-timer.C:
		process.closeStatus()
		return false, false
	}
}

func (process *controlWorkerProcess) closeStatus() {
	if process == nil {
		return
	}
	process.closeOnce.Do(func() {
		if process.statusReader != nil {
			_ = process.statusReader.Close()
		}
	})
}

func (process *controlWorkerProcess) signalGroup(signal syscall.Signal) bool {
	if process == nil || process.pid <= 1 {
		return false
	}
	group, err := syscall.Getpgid(process.pid)
	if err == nil && group != process.pid {
		return false
	}
	if err != nil && !(errors.Is(err, syscall.ESRCH) && process.exited()) {
		return false
	}
	err = syscall.Kill(-process.pid, signal)
	return err == nil || errors.Is(err, syscall.ESRCH)
}

func (process *controlWorkerProcess) processGroupGone() bool {
	if process == nil || process.pid <= 1 {
		return false
	}
	err := syscall.Kill(-process.pid, 0)
	return errors.Is(err, syscall.ESRCH)
}

func waitPIDFD(descriptor int) error {
	if descriptor < 0 {
		return errChildStop
	}
	descriptors := []unix.PollFd{{Fd: int32(descriptor), Events: unix.POLLIN}}
	for {
		count, err := unix.Poll(descriptors, -1)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil || count != 1 ||
			descriptors[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 ||
			descriptors[0].Revents&(unix.POLLNVAL|unix.POLLERR) != 0 {
			return errChildStop
		}
		return nil
	}
}
