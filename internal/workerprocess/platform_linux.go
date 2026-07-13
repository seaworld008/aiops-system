//go:build linux

package workerprocess

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/seaworld008/aiops-system/internal/workerbootstrap"
	"golang.org/x/sys/unix"
)

const controlWorkerExecutable = "/proc/self/exe"

const sourceLoaderKillConfirmation = 5 * time.Second

type sourceLoadResult struct {
	source controlWorkerSource
	err    error
}

func openProductionControlWorkerSource(ctx context.Context, timeout time.Duration) (controlWorkerSource, error) {
	pidFD := -1
	return loadControlWorkerSourceFromCommand(ctx, timeout, buildSourceLoaderCommand(&pidFD))
}

func buildSourceLoaderCommand(pidFD *int) *exec.Cmd {
	command := exec.Command(controlWorkerExecutable, controlWorkerLoaderArgument)
	command.Args = []string{controlWorkerExecutable, controlWorkerLoaderArgument}
	command.Env = []string{}
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = nil
	command.WaitDelay = controlWorkerWaitDelay
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: pidFD}
	return command
}

func productionControlWorkerSecretSupplier(
	ctx context.Context,
	timeout time.Duration,
	postgres *os.File,
	starter *os.File,
	control *os.File,
) error {
	pidFD := -1
	return supplyControlWorkerSecretsFromCommand(
		ctx,
		timeout,
		buildSecretLoaderCommand(&pidFD),
		postgres,
		starter,
		control,
	)
}

func buildSecretLoaderCommand(pidFD *int) *exec.Cmd {
	command := exec.Command(controlWorkerExecutable, controlWorkerSecretLoaderArgument)
	command.Args = []string{controlWorkerExecutable, controlWorkerSecretLoaderArgument}
	command.Env = []string{}
	command.Dir = "/"
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = nil
	command.WaitDelay = controlWorkerWaitDelay
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: pidFD}
	return command
}

func supplyControlWorkerSecretsFromCommand(
	ctx context.Context,
	timeout time.Duration,
	command *exec.Cmd,
	postgres *os.File,
	starter *os.File,
	control *os.File,
) error {
	if !validFixedSecretLoaderCommand(command) {
		return errChildStart
	}
	return supplyControlWorkerSecretsFromCommandUnchecked(
		ctx,
		timeout,
		command,
		postgres,
		starter,
		control,
	)
}

func supplyControlWorkerSecretsFromCommandUnchecked(
	ctx context.Context,
	timeout time.Duration,
	command *exec.Cmd,
	postgres *os.File,
	starter *os.File,
	control *os.File,
) error {
	writers := [3]*os.File{postgres, starter, control}
	if ctx == nil || ctx.Err() != nil || timeout <= 0 || command == nil || command.Process != nil ||
		len(command.ExtraFiles) != 0 || command.SysProcAttr == nil || command.SysProcAttr.PidFD == nil ||
		!validSecretLoaderWriters(writers) {
		return errChildStart
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if time.Until(deadline) <= 0 || startSecretLoaderCommand(command, writers) != nil {
		return errChildStart
	}
	// Start has duplicated the three write capabilities into child FD3-FD5.
	// Drop the supervisor copies immediately so EOF is controlled solely by the
	// short-lived loader, never by the long-lived parent.
	closeControlWorkerFiles(writers[:])
	pidFD := *command.SysProcAttr.PidFD
	if pidFD < 0 {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = containStartedCommandWithoutPIDFD(command, nil, sourceLoaderKillConfirmation)
		return errChildStart
	}
	exitDone := make(chan struct{})
	var exitTrusted atomic.Bool
	go func() {
		exitTrusted.Store(waitPIDFD(pidFD) == nil)
		close(exitDone)
	}()
	remaining := time.Until(deadline)
	if remaining <= 0 {
		remaining = time.Nanosecond
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	kill := false
	select {
	case <-exitDone:
		if !exitTrusted.Load() {
			kill = true
		}
	case <-ctx.Done():
		kill = true
	case <-timer.C:
		kill = true
	}
	contained, waitErr := finalizeSourceLoader(
		command,
		nil,
		pidFD,
		exitDone,
		&exitTrusted,
		kill,
		sourceLoaderKillConfirmation,
	)
	if kill || !contained || waitErr != nil || ctx.Err() != nil || time.Until(deadline) <= 0 {
		return errChildStart
	}
	return nil
}

func validFixedSecretLoaderCommand(command *exec.Cmd) bool {
	if command == nil || command.Path != controlWorkerExecutable || len(command.Args) != 2 ||
		command.Args[0] != controlWorkerExecutable || command.Args[1] != controlWorkerSecretLoaderArgument ||
		command.Env == nil || len(command.Env) != 0 || command.Dir != "/" || command.Stdin != nil ||
		command.Stdout != io.Discard || command.Stderr != io.Discard || len(command.ExtraFiles) != 0 ||
		command.WaitDelay != controlWorkerWaitDelay || command.Cancel != nil || command.Process != nil ||
		command.ProcessState != nil || command.Err != nil || command.SysProcAttr == nil ||
		command.SysProcAttr.PidFD == nil || *command.SysProcAttr.PidFD != -1 {
		return false
	}
	want := &syscall.SysProcAttr{
		Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: command.SysProcAttr.PidFD,
	}
	return reflect.DeepEqual(command.SysProcAttr, want)
}

func startSecretLoaderCommand(command *exec.Cmd, writers [3]*os.File) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = errChildStart
		}
		if command != nil {
			command.ExtraFiles = nil
		}
	}()
	if command == nil || command.Process != nil || len(command.ExtraFiles) != 0 ||
		!validSecretLoaderWriters(writers) {
		return errChildStart
	}
	command.ExtraFiles = []*os.File{writers[0], writers[1], writers[2]}
	if err := command.Start(); err != nil {
		return errChildStart
	}
	return nil
}

func validSecretLoaderWriters(writers [3]*os.File) bool {
	seen := make(map[[2]uint64]struct{}, len(writers))
	for _, writer := range writers {
		if writer == nil {
			return false
		}
		var stat unix.Stat_t
		flags, flagsErr := unix.FcntlInt(writer.Fd(), unix.F_GETFL, 0)
		descriptorFlags, descriptorErr := unix.FcntlInt(writer.Fd(), unix.F_GETFD, 0)
		if unix.Fstat(int(writer.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO ||
			flagsErr != nil || flags&unix.O_ACCMODE != unix.O_WRONLY || descriptorErr != nil ||
			descriptorFlags&unix.FD_CLOEXEC == 0 {
			return false
		}
		identity := [2]uint64{uint64(stat.Dev), stat.Ino}
		if _, duplicate := seen[identity]; duplicate {
			return false
		}
		seen[identity] = struct{}{}
	}
	return true
}

func loadControlWorkerSourceFromCommand(
	ctx context.Context,
	timeout time.Duration,
	command *exec.Cmd,
) (controlWorkerSource, error) {
	if !validFixedSourceLoaderCommand(command) {
		return nil, errChildStart
	}
	return loadControlWorkerSourceFromCommandUnchecked(ctx, timeout, command)
}

func loadControlWorkerSourceFromCommandUnchecked(
	ctx context.Context,
	timeout time.Duration,
	command *exec.Cmd,
) (controlWorkerSource, error) {
	if ctx == nil || ctx.Err() != nil || timeout <= 0 || command == nil || command.Process != nil ||
		len(command.ExtraFiles) != 0 || command.SysProcAttr == nil || command.SysProcAttr.PidFD == nil {
		return nil, errChildStart
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, errChildStart
	}
	if startSourceLoaderCommand(command, writer) != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, errChildStart
	}
	_ = writer.Close()
	pidFD := *command.SysProcAttr.PidFD
	if pidFD < 0 {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = containStartedCommandWithoutPIDFD(command, reader, sourceLoaderKillConfirmation)
		return nil, errChildStart
	}
	loaded := make(chan sourceLoadResult, 1)
	go func() {
		source, receiveErr := receiveProductionControlWorkerSource(reader)
		loaded <- sourceLoadResult{source: source, err: receiveErr}
	}()
	exitDone := make(chan struct{})
	var exitTrusted atomic.Bool
	go func() {
		exitTrusted.Store(waitPIDFD(pidFD) == nil)
		close(exitDone)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var result sourceLoadResult
	received := false
	exited := false
	loadSignal := (<-chan sourceLoadResult)(loaded)
	exitSignal := (<-chan struct{})(exitDone)
	kill := false
	failed := false
	for !received || !exited {
		select {
		case result = <-loadSignal:
			received = true
			loadSignal = nil
			if result.err != nil || nilControlWorkerSource(result.source) {
				failed = true
				kill = true
			}
		case <-exitSignal:
			exited = true
			exitSignal = nil
			if !exitTrusted.Load() {
				failed = true
				kill = true
			}
		case <-ctx.Done():
			failed = true
			kill = true
		case <-timer.C:
			failed = true
			kill = true
		}
		if failed {
			break
		}
	}
	contained, waitErr := finalizeSourceLoader(command, reader, pidFD, exitDone, &exitTrusted, kill, timeout)
	if !received {
		discardSourceLoad(loaded, result, false)
	}
	if failed || !contained || waitErr != nil || result.err != nil || nilControlWorkerSource(result.source) {
		_ = closeControlWorkerSource(result.source)
		return nil, errChildStart
	}
	if ctx.Err() != nil {
		_ = closeControlWorkerSource(result.source)
		return nil, errChildStart
	}
	return result.source, nil
}

func validFixedSourceLoaderCommand(command *exec.Cmd) bool {
	if command == nil || command.Path != controlWorkerExecutable || len(command.Args) != 2 ||
		command.Args[0] != controlWorkerExecutable || command.Args[1] != controlWorkerLoaderArgument ||
		command.Env == nil || len(command.Env) != 0 || command.Dir != "/" || command.Stdin != nil ||
		command.Stdout != io.Discard || command.Stderr != io.Discard || len(command.ExtraFiles) != 0 ||
		command.WaitDelay != controlWorkerWaitDelay || command.Cancel != nil || command.Process != nil ||
		command.ProcessState != nil || command.Err != nil || command.SysProcAttr == nil ||
		command.SysProcAttr.PidFD == nil || *command.SysProcAttr.PidFD != -1 {
		return false
	}
	want := &syscall.SysProcAttr{
		Setpgid: true, Pdeathsig: syscall.SIGKILL, PidFD: command.SysProcAttr.PidFD,
	}
	return reflect.DeepEqual(command.SysProcAttr, want)
}

func startSourceLoaderCommand(command *exec.Cmd, writer *os.File) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = errChildStart
		}
		if command != nil {
			command.ExtraFiles = nil
		}
	}()
	if command == nil || writer == nil || command.Process != nil || len(command.ExtraFiles) != 0 {
		return errChildStart
	}
	command.ExtraFiles = []*os.File{writer}
	if err := command.Start(); err != nil {
		return errChildStart
	}
	return nil
}

func receiveProductionControlWorkerSource(reader *os.File) (source controlWorkerSource, returnedErr error) {
	if reader != nil {
		defer reader.Close()
	}
	defer func() {
		if recover() != nil {
			source = nil
			returnedErr = errChildStart
		}
	}()
	source, err := workerbootstrap.ReceiveProductionSource(reader)
	if err != nil || nilControlWorkerSource(source) {
		_ = closeControlWorkerSource(source)
		return nil, errChildStart
	}
	return source, nil
}

func discardSourceLoad(loaded <-chan sourceLoadResult, current sourceLoadResult, received bool) {
	_ = closeControlWorkerSource(current.source)
	if received || loaded == nil {
		return
	}
	timer := time.NewTimer(sourceLoaderKillConfirmation)
	defer timer.Stop()
	select {
	case late := <-loaded:
		_ = closeControlWorkerSource(late.source)
	case <-timer.C:
	}
}

func closeControlWorkerSource(source controlWorkerSource) error {
	if nilControlWorkerSource(source) {
		return nil
	}
	return invokeControlWorkerSourceClose(source)
}

func finalizeSourceLoader(
	command *exec.Cmd,
	reader *os.File,
	pidFD int,
	exitDone <-chan struct{},
	exitTrusted *atomic.Bool,
	kill bool,
	timeout time.Duration,
) (bool, error) {
	if reader != nil {
		_ = reader.Close()
	}
	if command == nil || command.Process == nil || command.Process.Pid <= 1 || pidFD < 0 ||
		exitDone == nil || exitTrusted == nil || timeout <= 0 {
		if pidFD >= 0 {
			_ = unix.Close(pidFD)
		}
		return false, errChildStart
	}
	pid := command.Process.Pid
	killOK := true
	if kill {
		killErr := syscall.Kill(-pid, syscall.SIGKILL)
		killOK = killErr == nil || errors.Is(killErr, syscall.ESRCH)
	}
	confirmation := sourceLoaderKillConfirmation
	if timeout < confirmation {
		confirmation = timeout
	}
	timer := time.NewTimer(confirmation)
	defer timer.Stop()
	select {
	case <-exitDone:
	case <-timer.C:
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = unix.Close(pidFD)
		startSourceLoaderFailStopReaper(command)
		return false, errChildStart
	}
	trusted := exitTrusted.Load()
	if !trusted {
		// A closed exitDone only proves the pidfd poll goroutine returned. If the
		// poll itself was untrusted, never enter Wait: the leader may still be in
		// uninterruptible sleep. Trigger process-level fail-stop; the fixed
		// Pdeathsig contains the child when cmd/worker exits.
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = unix.Close(pidFD)
		startSourceLoaderFailStopReaper(command)
		return false, errChildStart
	}
	probe := &controlWorkerProcess{pid: pid}
	members, groupTrusted := probe.groupHasOtherMembers()
	groupClean := groupTrusted && !members
	if !groupTrusted || members {
		killErr := syscall.Kill(-pid, syscall.SIGKILL)
		killOK = killOK && (killErr == nil || errors.Is(killErr, syscall.ESRCH))
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		members, groupTrusted = probe.groupHasOtherMembers()
		if groupTrusted && !members {
			break
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			_ = unix.Close(pidFD)
			startSourceLoaderFailStopReaper(command)
			return false, errChildStart
		}
	}
	// pidfd has proved the leader exited and every other original-PGID member
	// is gone. With fixed io.Discard outputs and WaitDelay, this sole Wait is a
	// local reap and cannot depend on the fixed-root filesystem.
	waitErr := command.Wait()
	closeErr := unix.Close(pidFD)
	groupGone := errors.Is(syscall.Kill(-pid, 0), syscall.ESRCH)
	return killOK && trusted && groupTrusted && groupClean && groupGone && closeErr == nil, waitErr
}

func startSourceLoaderFailStopReaper(command *exec.Cmd) {
	if command == nil || command.Process == nil || command.ProcessState != nil {
		return
	}
	go func() { _ = command.Wait() }()
}

type childEvent uint8

const (
	childEventSecretReady childEvent = iota + 1
	childEventReady
	childEventFatal
	childEventProtocol
	childEventStatusClosed
)

type controlWorkerProcess struct {
	command       *exec.Cmd
	pid           int
	pidFD         int
	statusReader  *os.File
	secretMu      sync.Mutex
	secretWriter  [3]*os.File
	secretClaimed bool
	exitDone      chan struct{}
	exitTrusted   atomic.Bool
	reapDone      chan struct{}
	reapOnce      sync.Once
	waitErr       error
	closeOnce     sync.Once
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
	return acceptControlWorkerChildWithSource(acceptInheritedControlWorkerSource, true)
}

func acceptControlWorkerChildWithSource(
	acceptSource func() (io.Closer, error),
	enforceInheritedDescriptors bool,
) (*ChildStatus, error) {
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
	if enforceInheritedDescriptors &&
		(!onlyExpectedInheritedDescriptors(controlWorkerControlFD) || !fixedInheritedDescriptorsAreDistinct()) {
		_ = file.Close()
		return nil, errInvalidChildInvocation
	}
	source, err := invokeInheritedSourceAccept(acceptSource)
	if err != nil || nilIOCloser(source) {
		_ = file.Close()
		return nil, errInvalidChildInvocation
	}
	return newChildStatus(file, source), nil
}

func fixedInheritedDescriptorsAreDistinct() bool {
	return inheritedDescriptorRangeIsDistinct(int(controlWorkerStatusFD), controlWorkerControlFD)
}

func inheritedDescriptorRangeIsDistinct(minimum, maximum int) bool {
	if minimum < 0 || maximum < minimum {
		return false
	}
	seen := make(map[[2]uint64]struct{}, maximum-minimum+1)
	for descriptor := minimum; descriptor <= maximum; descriptor++ {
		var stat unix.Stat_t
		if unix.Fstat(descriptor, &stat) != nil {
			return false
		}
		identity := [2]uint64{uint64(stat.Dev), stat.Ino}
		if _, duplicate := seen[identity]; duplicate {
			return false
		}
		seen[identity] = struct{}{}
	}
	return true
}

func onlyExpectedInheritedDescriptors(maximum int) bool {
	if maximum < 2 {
		return false
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		descriptor, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || descriptor <= maximum {
			continue
		}
		flags, flagsErr := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0)
		if errors.Is(flagsErr, syscall.EBADF) {
			continue
		}
		if flagsErr != nil || flags&unix.FD_CLOEXEC == 0 {
			return false
		}
	}
	return true
}

func runControlWorkerSourceLoaderChild() error {
	if len(os.Environ()) != 0 {
		return errInvalidChildInvocation
	}
	workingDirectory, err := os.Getwd()
	if err != nil || workingDirectory != "/" {
		return errInvalidChildInvocation
	}
	pid := os.Getpid()
	group, groupErr := syscall.Getpgid(0)
	deathSignal, deathErr := currentParentDeathSignal()
	if groupErr != nil || deathErr != nil || pid <= 1 || group != pid || os.Getppid() <= 0 ||
		deathSignal != syscall.SIGKILL {
		return errInvalidChildInvocation
	}
	unix.CloseOnExec(int(controlWorkerStatusFD))
	if !onlyExpectedInheritedDescriptors(int(controlWorkerStatusFD)) {
		return errInvalidChildInvocation
	}
	if err := workerbootstrap.WriteProductionSourceToLoaderFD(); err != nil {
		return errInvalidChildInvocation
	}
	return nil
}

func runControlWorkerSecretLoaderChild() error {
	if len(os.Environ()) != 0 {
		return errInvalidChildInvocation
	}
	workingDirectory, err := os.Getwd()
	if err != nil || workingDirectory != "/" {
		return errInvalidChildInvocation
	}
	pid := os.Getpid()
	group, groupErr := syscall.Getpgid(0)
	deathSignal, deathErr := currentParentDeathSignal()
	if groupErr != nil || deathErr != nil || pid <= 1 || group != pid || os.Getppid() <= 0 ||
		deathSignal != syscall.SIGKILL ||
		!inheritedDescriptorRangeIsDistinct(
			int(controlWorkerStatusFD),
			controlWorkerSecretLoaderMaxFD,
		) {
		return errInvalidChildInvocation
	}
	for descriptor := int(controlWorkerStatusFD); descriptor <= controlWorkerSecretLoaderMaxFD; descriptor++ {
		unix.CloseOnExec(descriptor)
	}
	if !onlyExpectedInheritedDescriptors(controlWorkerSecretLoaderMaxFD) {
		return errInvalidChildInvocation
	}
	if err := workerbootstrap.WriteProductionSecretsToLoaderFDs(); err != nil {
		return errInvalidChildInvocation
	}
	return nil
}

func acceptInheritedControlWorkerSource() (io.Closer, error) {
	return workerbootstrap.AcceptInheritedSource()
}

func invokeInheritedSourceAccept(accept func() (io.Closer, error)) (source io.Closer, returnedErr error) {
	defer func() {
		if recover() != nil {
			source = nil
			returnedErr = errInvalidChildInvocation
		}
	}()
	if accept == nil {
		return nil, errInvalidChildInvocation
	}
	source, err := accept()
	if err != nil || nilIOCloser(source) {
		if !nilIOCloser(source) {
			_ = source.Close()
		}
		return nil, errInvalidChildInvocation
	}
	return source, nil
}

func nilIOCloser(value io.Closer) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
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
	startupDeadline := time.Now().Add(settings.startupTimeout)
	source, err := invokeControlWorkerSourceOpen(settings.openSource, ctx, settings.startupTimeout)
	if err != nil || nilControlWorkerSource(source) {
		return errChildStart
	}
	if ctx.Err() != nil {
		_ = invokeControlWorkerSourceClose(source)
		return errChildStart
	}
	remaining := time.Until(startupDeadline)
	if remaining <= 0 {
		_ = invokeControlWorkerSourceClose(source)
		return errChildStart
	}
	process, events, outputExceeded, err := startControlWorker(settings, source)
	if err != nil {
		return errChildStart
	}
	remaining = time.Until(startupDeadline)
	if remaining <= 0 {
		return terminateControlWorker(
			process, settings, events, outputExceeded,
			settings.startupGrace, errChildStartup, errChildStartup,
		)
	}
	startup := time.NewTimer(remaining)
	defer startup.Stop()
	var secretSupply *controlWorkerSecretSupplyOperation
	var secretSupplySignal <-chan error
	stopSecretSupply := func() {
		if secretSupply != nil {
			secretSupply.cancelAndWait()
			secretSupply = nil
			secretSupplySignal = nil
		}
	}
	defer stopSecretSupply()
	rejectStartup := func(cause error) error {
		stopSecretSupply()
		return rejectAfterContainment(process, settings, cause)
	}
	terminateStartup := func(grace time.Duration, cleanResult error, exitFallback error) error {
		stopSecretSupply()
		return terminateControlWorker(
			process,
			settings,
			events,
			outputExceeded,
			grace,
			cleanResult,
			exitFallback,
		)
	}
	secretSupplied := false
	for {
		select {
		case event, ok := <-events:
			if !ok {
				return rejectStartup(errChildProtocol)
			}
			switch event {
			case childEventSecretReady:
				if secretSupply != nil || secretSupplied {
					return rejectStartup(errChildProtocol)
				}
				if ctx.Err() != nil {
					return terminateStartup(settings.startupGrace, nil, errChildStartup)
				}
				remaining = time.Until(startupDeadline)
				if remaining <= 0 {
					return terminateStartup(settings.startupGrace, errChildStartup, errChildStartup)
				}
				secretSupply = beginControlWorkerSecretSupply(ctx, remaining, settings.supplySecrets, process)
				secretSupplySignal = secretSupply.result
			case childEventReady:
				if time.Until(startupDeadline) <= 0 {
					return terminateStartup(settings.startupGrace, errChildStartup, errChildStartup)
				}
				if !secretSupplied {
					select {
					case supplyErr := <-secretSupplySignal:
						secretSupply.finish()
						secretSupply = nil
						secretSupplySignal = nil
						if supplyErr != nil {
							return rejectStartup(errChildStart)
						}
						if time.Until(startupDeadline) <= 0 {
							return terminateStartup(settings.startupGrace, errChildStartup, errChildStartup)
						}
						secretSupplied = true
					default:
						return rejectStartup(errChildProtocol)
					}
				}
				return superviseReadyControlWorker(ctx, settings, process, events, outputExceeded)
			case childEventFatal:
				return rejectStartup(errChildFatal)
			default:
				return rejectStartup(errChildProtocol)
			}
		case <-outputExceeded:
			return rejectStartup(errOutputLimit)
		case <-process.exitDone:
			cause := classifyExitedControlWorker(events, outputExceeded, errChildStartup)
			return rejectStartup(cause)
		case <-startup.C:
			return terminateStartup(settings.startupGrace, errChildStartup, errChildStartup)
		case <-ctx.Done():
			return terminateStartup(settings.startupGrace, nil, errChildStartup)
		case supplyErr := <-secretSupplySignal:
			secretSupply.finish()
			secretSupply = nil
			secretSupplySignal = nil
			if supplyErr != nil {
				return rejectStartup(errChildStart)
			}
			if time.Until(startupDeadline) <= 0 {
				return terminateStartup(settings.startupGrace, errChildStartup, errChildStartup)
			}
			secretSupplied = true
		}
	}
}

type controlWorkerSecretSupplyOperation struct {
	result chan error
	done   chan struct{}
	cancel context.CancelFunc
}

func beginControlWorkerSecretSupply(
	ctx context.Context,
	timeout time.Duration,
	supplier controlWorkerSecretSupplier,
	process *controlWorkerProcess,
) *controlWorkerSecretSupplyOperation {
	supplyCtx, cancel := context.WithCancel(ctx)
	operation := &controlWorkerSecretSupplyOperation{
		result: make(chan error, 1),
		done:   make(chan struct{}),
		cancel: cancel,
	}
	go func() {
		operation.result <- process.supplySecrets(supplyCtx, timeout, supplier)
		// The completion result is buffered before EOF is published. Therefore a
		// child cannot legitimately report READY before the supervisor can prove
		// that the supplier returned successfully.
		process.closeSecretWriters()
		close(operation.done)
	}()
	return operation
}

func (operation *controlWorkerSecretSupplyOperation) finish() {
	if operation == nil {
		return
	}
	<-operation.done
	operation.cancel()
}

func (operation *controlWorkerSecretSupplyOperation) cancelAndWait() {
	if operation == nil {
		return
	}
	operation.cancel()
	<-operation.done
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
		case event, ok := <-events:
			if !ok {
				return rejectAfterContainment(process, settings, errChildProtocol)
			}
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
			return terminateControlWorker(
				process, settings, events, outputExceeded,
				settings.shutdownGrace, nil, errChildExit,
			)
		}
	}
}

func startControlWorker(
	settings supervisorSettings,
	source controlWorkerSource,
) (*controlWorkerProcess, <-chan childEvent, <-chan struct{}, error) {
	if nilControlWorkerSource(source) {
		return nil, nil, nil, errChildStart
	}
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		_ = invokeControlWorkerSourceClose(source)
		return nil, nil, nil, errChildStart
	}
	secretReaders, secretWriters, err := openControlWorkerSecretPipes()
	if err != nil {
		_ = statusReader.Close()
		_ = statusWriter.Close()
		_ = invokeControlWorkerSourceClose(source)
		return nil, nil, nil, errChildStart
	}
	output := newBoundedDiscard(settings.outputLimit)
	pidFD := -1
	command := buildControlWorkerCommand(settings, output, &pidFD)
	startErr := invokeControlWorkerSourceStart(source, command, statusWriter, secretReaders)
	closeErr := invokeControlWorkerSourceClose(source)
	var process *controlWorkerProcess
	if command.Process != nil && pidFD >= 0 {
		process = newStartedControlWorkerProcess(command, pidFD, statusReader, secretWriters)
	}
	closeControlWorkerFiles(secretReaders[:])
	if startErr != nil || closeErr != nil || process == nil {
		_ = statusWriter.Close()
		if process != nil {
			_ = forceKillAndReap(process, settings.killConfirm)
		} else if command.Process != nil {
			closeControlWorkerFiles(secretWriters[:])
			_ = containStartedCommandWithoutPIDFD(command, statusReader, settings.killConfirm)
		} else {
			closeControlWorkerFiles(secretWriters[:])
			_ = statusReader.Close()
		}
		return nil, nil, nil, errChildStart
	}
	_ = statusWriter.Close()
	events := make(chan childEvent, 4)
	go monitorChildStatus(statusReader, events)
	return process, events, output.exceeded, nil
}

func newStartedControlWorkerProcess(
	command *exec.Cmd,
	pidFD int,
	statusReader *os.File,
	secretWriters [3]*os.File,
) *controlWorkerProcess {
	process := &controlWorkerProcess{
		command:      command,
		pid:          command.Process.Pid,
		pidFD:        pidFD,
		statusReader: statusReader,
		secretWriter: secretWriters,
		exitDone:     make(chan struct{}),
		reapDone:     make(chan struct{}),
	}
	go func() {
		process.exitTrusted.Store(waitPIDFD(pidFD) == nil)
		close(process.exitDone)
	}()
	return process
}

func openControlWorkerSecretPipes() (readers [3]*os.File, writers [3]*os.File, returnedErr error) {
	defer func() {
		if returnedErr != nil {
			closeControlWorkerFiles(readers[:])
			closeControlWorkerFiles(writers[:])
			readers = [3]*os.File{}
			writers = [3]*os.File{}
		}
	}()
	for index := range readers {
		reader, writer, err := os.Pipe()
		if err != nil {
			return readers, writers, errChildStart
		}
		readers[index] = reader
		writers[index] = writer
	}
	return readers, writers, nil
}

func closeControlWorkerFiles(files []*os.File) {
	for index := range files {
		if files[index] != nil {
			_ = files[index].Close()
			files[index] = nil
		}
	}
}

func buildControlWorkerCommand(
	settings supervisorSettings,
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
	command.ExtraFiles = nil
	command.WaitDelay = controlWorkerWaitDelay
	command.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
		PidFD:     pidFD,
	}
	return command
}

func invokeControlWorkerSourceOpen(
	open func(context.Context, time.Duration) (controlWorkerSource, error),
	ctx context.Context,
	timeout time.Duration,
) (source controlWorkerSource, returnedErr error) {
	defer func() {
		if recover() != nil {
			source = nil
			returnedErr = errChildStart
		}
	}()
	if open == nil || ctx == nil || timeout <= 0 {
		return nil, errChildStart
	}
	source, err := open(ctx, timeout)
	if err != nil || nilControlWorkerSource(source) {
		if !nilControlWorkerSource(source) {
			_ = source.Close()
		}
		return nil, errChildStart
	}
	return source, nil
}

func invokeControlWorkerSourceStart(
	source controlWorkerSource,
	command *exec.Cmd,
	status *os.File,
	secrets [3]*os.File,
) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = errChildStart
		}
	}()
	if nilControlWorkerSource(source) || command == nil || status == nil ||
		source.StartChild(command, status, secrets[0], secrets[1], secrets[2]) != nil {
		return errChildStart
	}
	return nil
}

func (process *controlWorkerProcess) supplySecrets(
	ctx context.Context,
	timeout time.Duration,
	supplier controlWorkerSecretSupplier,
) (returnedErr error) {
	writers, ok := process.claimSecretWriters()
	if !ok || ctx == nil || timeout <= 0 || supplier == nil {
		return errChildStart
	}
	supplyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if supplyCtx.Err() != nil {
		return errChildStart
	}
	defer func() {
		if recover() != nil {
			returnedErr = errChildStart
		}
	}()
	if supplier(supplyCtx, timeout, writers[0], writers[1], writers[2]) != nil {
		return errChildStart
	}
	return nil
}

func (process *controlWorkerProcess) claimSecretWriters() ([3]*os.File, bool) {
	if process == nil {
		return [3]*os.File{}, false
	}
	process.secretMu.Lock()
	defer process.secretMu.Unlock()
	writers := process.secretWriter
	if process.secretClaimed || writers[0] == nil || writers[1] == nil || writers[2] == nil {
		return [3]*os.File{}, false
	}
	process.secretClaimed = true
	return writers, true
}

func (process *controlWorkerProcess) closeSecretWriters() {
	if process == nil {
		return
	}
	process.secretMu.Lock()
	writers := process.secretWriter
	process.secretWriter = [3]*os.File{}
	process.secretClaimed = true
	process.secretMu.Unlock()
	closeControlWorkerFiles(writers[:])
}

func invokeControlWorkerSourceClose(source controlWorkerSource) (returnedErr error) {
	defer func() {
		if recover() != nil {
			returnedErr = errChildStart
		}
	}()
	if nilControlWorkerSource(source) || source.Close() != nil {
		return errChildStart
	}
	return nil
}

func containStartedCommandWithoutPIDFD(
	command *exec.Cmd,
	statusReader *os.File,
	killConfirm time.Duration,
) bool {
	if command == nil || command.Process == nil || command.Process.Pid <= 1 || killConfirm <= 0 {
		if statusReader != nil {
			_ = statusReader.Close()
		}
		return false
	}
	pid := command.Process.Pid
	group, groupErr := syscall.Getpgid(pid)
	killErr := error(nil)
	if groupErr == nil && group == pid {
		killErr = syscall.Kill(-pid, syscall.SIGKILL)
	} else {
		killErr = command.Process.Kill()
	}
	waitDone := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(waitDone)
	}()
	timer := time.NewTimer(killConfirm)
	defer timer.Stop()
	select {
	case <-waitDone:
	case <-timer.C:
		if statusReader != nil {
			_ = statusReader.Close()
		}
		return false
	}
	if statusReader != nil {
		_ = statusReader.Close()
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if errors.Is(syscall.Kill(-pid, 0), syscall.ESRCH) {
			return killErr == nil || errors.Is(killErr, syscall.ESRCH)
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			return false
		}
	}
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
		case event, ok := <-events:
			if !ok {
				return cause
			}
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
	defer close(events)
	state := childStatusOpen
	buffer := make([]byte, 32)
	for {
		read, err := reader.Read(buffer)
		for _, value := range buffer[:read] {
			switch {
			case state == childStatusOpen && value == controlWorkerSecretReadyByte:
				state = childStatusSecretReady
				events <- childEventSecretReady
			case state == childStatusSecretReady && value == controlWorkerReadyByte:
				state = childStatusReady
				events <- childEventReady
			case (state == childStatusOpen || state == childStatusSecretReady || state == childStatusReady) &&
				value == controlWorkerFatalByte:
				state = childStatusClosed
				events <- childEventFatal
			default:
				state = childStatusClosed
				events <- childEventProtocol
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				events <- childEventProtocol
			} else if state != childStatusClosed {
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

func terminateControlWorker(
	process *controlWorkerProcess,
	settings supervisorSettings,
	events <-chan childEvent,
	outputExceeded <-chan struct{},
	grace time.Duration,
	cleanResult error,
	exitFallback error,
) error {
	if process != nil {
		process.closeSecretWriters()
	}
	if process == nil || grace <= 0 {
		_ = forceKillAndReap(process, settings.killConfirm)
		return errChildStop
	}
	if cause, observed := terminationPreflight(events, outputExceeded, process.exitDone, exitFallback); observed {
		return rejectAfterContainment(process, settings, cause)
	}
	if !process.signalGroup(syscall.SIGTERM) {
		_ = forceKillAndReap(process, settings.killConfirm)
		return errChildStop
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	exitDone := process.exitDone
	exited := false
	statusTerminal := false
	for {
		if exited {
			members, trusted := process.groupHasOtherMembers()
			if process.exitTrusted.Load() && trusted && !members {
				if !statusTerminal {
					if cause := classifyTerminatedControlWorker(events, outputExceeded); cause != nil {
						return rejectAfterContainment(process, settings, cause)
					}
				}
				reaped, clean := process.reapWithin(settings.killConfirm)
				if !reaped || !process.processGroupGone() {
					return errChildStop
				}
				// Cmd.Wait has now joined the bounded stdout/stderr copier, so this
				// non-blocking check observes its final state without racing a late
				// overflow notification.
				select {
				case <-outputExceeded:
					return errOutputLimit
				default:
				}
				if clean {
					return cleanResult
				}
				return errChildStop
			}
		}
		select {
		case event, ok := <-events:
			if !ok {
				statusTerminal = true
				events = nil
				continue
			}
			switch event {
			case childEventFatal:
				// TERM may already have entered the SDK Stop path. Do not send it
				// again: shorten the remaining window to anomaly containment, then
				// hard-stop and reap the entire original process group.
				return rejectAfterContainment(process, settings, errChildFatal)
			case childEventProtocol:
				return rejectAfterContainment(process, settings, errChildProtocol)
			case childEventSecretReady, childEventReady, childEventStatusClosed:
				// READY can race startup cancellation. Closing the status FD is
				// expected while a cooperative child exits after TERM. Neither is
				// sufficient to claim successful process containment.
			default:
				return rejectAfterContainment(process, settings, errChildProtocol)
			}
		case <-outputExceeded:
			return rejectAfterContainment(process, settings, errOutputLimit)
		case <-exitDone:
			exited = true
			exitDone = nil
		case <-ticker.C:
		case <-timer.C:
			_ = forceKillAndReap(process, settings.killConfirm)
			return errChildStop
		}
	}
}

func terminationPreflight(
	events <-chan childEvent,
	outputExceeded <-chan struct{},
	exitDone <-chan struct{},
	exitFallback error,
) (error, bool) {
	for {
		select {
		case event, ok := <-events:
			if !ok {
				return errChildProtocol, true
			}
			switch event {
			case childEventSecretReady, childEventReady:
				// READY can already be queued when startup cancellation or its
				// deadline wins. Drain it and keep looking for a following FATAL.
				continue
			case childEventFatal:
				return errChildFatal, true
			default:
				return errChildProtocol, true
			}
		case <-outputExceeded:
			return errOutputLimit, true
		case <-exitDone:
			return classifyExitedControlWorker(events, outputExceeded, exitFallback), true
		default:
			return nil, false
		}
	}
}

func classifyTerminatedControlWorker(
	events <-chan childEvent,
	outputExceeded <-chan struct{},
) error {
	timer := time.NewTimer(exitClassificationGrace)
	defer timer.Stop()
	for {
		select {
		case event, ok := <-events:
			if !ok {
				return nil
			}
			switch event {
			case childEventFatal:
				return errChildFatal
			case childEventProtocol:
				return errChildProtocol
			case childEventSecretReady, childEventReady, childEventStatusClosed:
				continue
			default:
				return errChildProtocol
			}
		case <-outputExceeded:
			return errOutputLimit
		case <-timer.C:
			return errChildProtocol
		}
	}
}

func rejectAfterContainment(process *controlWorkerProcess, settings supervisorSettings, cause error) error {
	if process != nil {
		process.closeSecretWriters()
	}
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
	if !contained {
		return forceKillAndReap(process, killConfirm)
	}
	reaped, _ := process.reapWithin(killConfirm)
	return reaped && process.processGroupGone()
}

func forceKillAndReap(process *controlWorkerProcess, killConfirm time.Duration) bool {
	if process == nil || killConfirm <= 0 {
		return false
	}
	process.closeSecretWriters()
	killOK := process.signalGroup(syscall.SIGKILL)
	if !killOK && process.command != nil && process.command.Process != nil {
		killOK = process.command.Process.Kill() == nil || process.exited()
	}
	contained := process.waitForContained(killConfirm)
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
		process.closeSecretWriters()
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
