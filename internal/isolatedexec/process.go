package isolatedexec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const processPipeDrainTimeout = 500 * time.Millisecond

type childProcess struct {
	command        *exec.Cmd
	pid            int
	stableHandle   int
	jobDirectory   string
	prepareWriter  *os.File
	goWriter       *os.File
	responseReader *os.File
	output         *outputBudget
	exitDone       chan struct{}
	exitMu         sync.Mutex
	exitErr        error
	waitDone       chan struct{}
	waitMu         sync.Mutex
	waitErr        error
	reapOnce       sync.Once
	closeOnce      sync.Once
	handleOnce     sync.Once
	cleanupOnce    sync.Once
	cleanupJob     func() error
	cleanupErr     error
}

type terminationResult struct {
	confirmed   bool
	waitErr     error
	boundaryErr error
}

func (supervisor *Supervisor) startProcess() (*childProcess, error) {
	if supervisor == nil || !supervisor.settings.valid() {
		return nil, ErrInvalidConfiguration
	}
	release, err := supervisor.reserveJob()
	if err != nil {
		return nil, err
	}
	jobDirectory, job, err := supervisor.createJobDirectory()
	if err != nil {
		release()
		return nil, err
	}
	cleanupJob := func() error {
		cleanupErr := supervisor.removeJobDirectory(jobDirectory, job)
		if cleanupErr == nil {
			release()
		}
		return cleanupErr
	}
	fail := func(cause error) (*childProcess, error) {
		return nil, errors.Join(cause, cleanupJob())
	}
	prepareReader, prepareWriter, err := os.Pipe()
	if err != nil {
		return fail(ErrInvalidConfiguration)
	}
	goReader, goWriter, err := os.Pipe()
	if err != nil {
		closeFiles(prepareReader, prepareWriter)
		return fail(ErrInvalidConfiguration)
	}
	responseReader, responseWriter, err := os.Pipe()
	if err != nil {
		closeFiles(prepareReader, prepareWriter, goReader, goWriter)
		return fail(ErrInvalidConfiguration)
	}
	budget := newOutputBudget(supervisor.settings.outputLimit)
	command := supervisor.buildCommand(jobDirectory, []*os.File{prepareReader, goReader, responseWriter}, budget)
	if command == nil || !supervisor.validateJobDirectory(jobDirectory, job) {
		closeFiles(prepareReader, prepareWriter, goReader, goWriter, responseReader, responseWriter)
		return fail(ErrInvalidConfiguration)
	}
	if err := command.Start(); err != nil {
		closeFiles(prepareReader, prepareWriter, goReader, goWriter, responseReader, responseWriter)
		return fail(ErrNotReady)
	}
	stableHandle := stableProcessHandle(command)
	if stableHandle < 0 {
		_ = command.Process.Kill()
		_ = command.Wait()
		closeFiles(prepareReader, prepareWriter, goReader, goWriter, responseReader, responseWriter)
		return fail(ErrUnsupportedPlatform)
	}
	closeFiles(prepareReader, goReader, responseWriter)
	process := &childProcess{
		command: command, pid: command.Process.Pid, stableHandle: stableHandle, jobDirectory: jobDirectory,
		prepareWriter: prepareWriter, goWriter: goWriter, responseReader: responseReader,
		output: budget, exitDone: make(chan struct{}), waitDone: make(chan struct{}),
		cleanupJob: cleanupJob,
	}
	go func() {
		exitErr := waitStableProcessExit(stableHandle)
		process.exitMu.Lock()
		process.exitErr = exitErr
		process.exitMu.Unlock()
		close(process.exitDone)
	}()
	return process, nil
}

func closeFiles(files ...*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func (process *childProcess) closePipes() {
	if process == nil {
		return
	}
	process.closeOnce.Do(func() {
		closeFiles(process.prepareWriter, process.goWriter, process.responseReader)
	})
}

func (process *childProcess) observedWaitError() error {
	if process == nil {
		return ErrTerminationUnconfirmed
	}
	select {
	case <-process.waitDone:
		process.waitMu.Lock()
		defer process.waitMu.Unlock()
		return process.waitErr
	default:
		return ErrTerminationUnconfirmed
	}
}

func (process *childProcess) observedExitError() error {
	if process == nil {
		return ErrTerminationUnconfirmed
	}
	select {
	case <-process.exitDone:
		process.exitMu.Lock()
		defer process.exitMu.Unlock()
		return process.exitErr
	default:
		return ErrTerminationUnconfirmed
	}
}

func (process *childProcess) reap() {
	if process == nil {
		return
	}
	process.reapOnce.Do(func() {
		waitErr := process.command.Wait()
		process.waitMu.Lock()
		process.waitErr = waitErr
		process.waitMu.Unlock()
		process.handleOnce.Do(func() { _ = closeStableProcessHandle(process.stableHandle) })
		close(process.waitDone)
	})
}

func (process *childProcess) signalGroup(signal syscall.Signal) error {
	if process == nil || process.pid <= 1 || process.stableHandle < 0 {
		return ErrTerminationUnconfirmed
	}
	select {
	case <-process.waitDone:
		return ErrTerminationUnconfirmed
	default:
	}
	select {
	case <-process.exitDone:
		// The original group leader is deliberately not reaped until every
		// descendant is gone, so its numeric PID/PGID cannot be reused. It is
		// therefore safe to finish terminating the reserved original group.
		return signalProcessGroup(process.pid, signal)
	default:
	}
	group, err := syscall.Getpgid(process.pid)
	if err != nil || group != process.pid {
		return ErrTerminationUnconfirmed
	}
	return signalProcessGroup(process.pid, signal)
}

func (process *childProcess) terminate(configuration settings) terminationResult {
	if process == nil || process.pid <= 1 {
		return terminationResult{boundaryErr: ErrTerminationUnconfirmed}
	}
	process.closePipes()
	termErr := process.signalGroup(syscall.SIGTERM)
	if process.waitForTermination(configuration.termGrace, false) {
		cleanupErr := process.cleanup(true)
		result := terminationResult{
			confirmed: cleanupErr == nil, waitErr: process.observedWaitError(),
			boundaryErr: errors.Join(termErr, cleanupErr),
		}
		if cleanupErr != nil {
			result.boundaryErr = errors.Join(result.boundaryErr, ErrTerminationUnconfirmed)
		}
		return result
	}
	killErr := process.signalGroup(syscall.SIGKILL)
	confirmed := process.waitForTermination(configuration.killConfirmTimeout, true)
	result := terminationResult{
		confirmed:   confirmed,
		waitErr:     process.observedWaitError(),
		boundaryErr: errors.Join(termErr, killErr),
	}
	if !confirmed {
		result.boundaryErr = errors.Join(result.boundaryErr, ErrTerminationUnconfirmed)
	}
	cleanupErr := process.cleanup(confirmed)
	if cleanupErr != nil {
		result.confirmed = false
		result.boundaryErr = errors.Join(result.boundaryErr, cleanupErr, ErrTerminationUnconfirmed)
	}
	return result
}

func (process *childProcess) awaitCleanExit(ctx context.Context, timeout time.Duration) terminationResult {
	if process == nil || ctx == nil || timeout <= 0 {
		return terminationResult{boundaryErr: ErrTerminationUnconfirmed}
	}
	process.closePipes()
	confirmed := process.waitForTerminationContext(ctx, timeout, false)
	result := terminationResult{confirmed: confirmed, waitErr: process.observedWaitError()}
	if !confirmed {
		result.boundaryErr = errors.Join(ctx.Err(), ErrTerminationUnconfirmed)
	}
	cleanupErr := process.cleanup(confirmed)
	if cleanupErr != nil {
		result.confirmed = false
		result.boundaryErr = errors.Join(result.boundaryErr, cleanupErr, ErrTerminationUnconfirmed)
	}
	return result
}

func (process *childProcess) waitForTermination(timeout time.Duration, reapAdopted bool) bool {
	return process.waitForTerminationContext(context.Background(), timeout, reapAdopted)
}

func (process *childProcess) waitForTerminationContext(ctx context.Context, timeout time.Duration, reapAdopted bool) bool {
	if process == nil || ctx == nil || timeout <= 0 {
		return false
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if process.terminationConfirmed(reapAdopted) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return process.terminationConfirmed(reapAdopted)
		case <-ticker.C:
		}
	}
}

func (process *childProcess) terminationConfirmed(reapAdopted bool) bool {
	if process == nil {
		return false
	}
	select {
	case <-process.exitDone:
	default:
		return false
	}
	if process.observedExitError() != nil {
		return false
	}
	if reapAdopted {
		if err := reapAdoptedProcessGroupZombies(process.pid, os.Getpid()); err != nil {
			return false
		}
	}
	members, err := processGroupHasMembersExceptLeader(process.pid)
	if err != nil || members {
		return false
	}
	process.reap()
	gone, err := processGroupGone(process.pid)
	if err != nil || !gone {
		return false
	}
	select {
	case <-process.waitDone:
		return true
	default:
		return false
	}
}

func (process *childProcess) cleanup(confirmed bool) error {
	if process == nil || !confirmed {
		return nil
	}
	process.cleanupOnce.Do(func() {
		if process.cleanupJob == nil {
			process.cleanupErr = ErrTerminationUnconfirmed
			return
		}
		process.cleanupErr = process.cleanupJob()
	})
	return process.cleanupErr
}

func (supervisor *Supervisor) createJobDirectory() (string, *runtimeJobDirectory, error) {
	if supervisor == nil {
		return "", nil, ErrInvalidConfiguration
	}
	if supervisor.boundary != nil {
		boundary := supervisor.boundary
		boundary.mu.RLock()
		defer boundary.mu.RUnlock()
		if boundary.closed || boundary.root == nil {
			return "", nil, ErrInvalidConfiguration
		}
		return createRuntimeJobDirectory(supervisor.settings.tempRoot, boundary.root, boundary.mount)
	}
	directory, err := createJobDirectory(supervisor.settings.tempRoot)
	return directory, nil, err
}

func (supervisor *Supervisor) validateJobDirectory(jobDirectory string, job *runtimeJobDirectory) bool {
	if supervisor == nil {
		return false
	}
	if supervisor.boundary == nil {
		return true
	}
	boundary := supervisor.boundary
	boundary.mu.RLock()
	defer boundary.mu.RUnlock()
	return !boundary.closed && boundary.root != nil &&
		validateRuntimeJobDirectory(supervisor.settings.tempRoot, boundary.root, boundary.mount, jobDirectory, job)
}

func (supervisor *Supervisor) removeJobDirectory(jobDirectory string, job *runtimeJobDirectory) error {
	if supervisor == nil {
		return ErrInvalidConfiguration
	}
	if supervisor.boundary == nil {
		return os.RemoveAll(jobDirectory)
	}
	boundary := supervisor.boundary
	boundary.mu.RLock()
	defer boundary.mu.RUnlock()
	if boundary.closed || boundary.root == nil {
		return ErrTerminationUnconfirmed
	}
	return removeRuntimeJobDirectory(boundary.root, jobDirectory, job)
}

func (supervisor *Supervisor) buildCommand(
	jobDirectory string,
	extraFiles []*os.File,
	budget *outputBudget,
) *exec.Cmd {
	if supervisor == nil {
		return nil
	}
	command := exec.Command(supervisor.executablePath)
	command.Args = []string{supervisor.executablePath}
	command.Env = []string{
		"HOME=" + jobDirectory,
		"LANG=C",
		"LC_ALL=C",
		"TMPDIR=" + jobDirectory,
	}
	command.Dir = jobDirectory
	command.Stdin = nil
	command.Stdout = budget
	command.Stderr = budget
	command.ExtraFiles = append([]*os.File(nil), extraFiles...)
	command.WaitDelay = processPipeDrainTimeout
	configureProcess(command)
	return command
}

func createJobDirectory(root string) (string, error) {
	if root == "" || len(root) > 4096 || !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		strings.TrimSpace(root) != root {
		return "", ErrInvalidConfiguration
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalidConfiguration
	}
	directory, err := os.MkdirTemp(root, "aiops-executor-")
	if err != nil {
		return "", ErrInvalidConfiguration
	}
	fail := func() (string, error) {
		_ = os.RemoveAll(directory)
		return "", ErrInvalidConfiguration
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fail()
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return fail()
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fail()
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		return fail()
	}
	return directory, nil
}
