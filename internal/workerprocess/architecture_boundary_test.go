package workerprocess_test

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/readassembly"
	"github.com/seaworld008/aiops-system/internal/workerprocess"
)

const workerProcessImport = "github.com/seaworld008/aiops-system/internal/workerprocess"

var (
	_ func() *workerprocess.ControlWorkerSupervisor                                     = workerprocess.NewControlWorkerSupervisor
	_ func([]string) bool                                                               = workerprocess.IsControlWorkerChild
	_ func([]string) (*workerprocess.ChildStatus, error)                                = workerprocess.AcceptControlWorkerChild
	_ func(context.Context, *workerprocess.ChildStatus) (*readassembly.Snapshot, error) = workerprocess.BuildControlWorkerSnapshot
	_ func(*workerprocess.ChildStatus) error                                            = workerprocess.ReportControlWorkerReady
	_ func(*workerprocess.ChildStatus)                                                  = workerprocess.ExitControlWorkerFatal
	_ func(*workerprocess.ChildStatus) error                                            = workerprocess.CloseControlWorkerChild
	_ interface{ Run(context.Context) error }                                           = (*workerprocess.ControlWorkerSupervisor)(nil)
)

type processBoundaryKey struct {
	file   string
	source string
	symbol string
}

type rawSyscallBoundaryKey struct {
	file     string
	source   string
	symbol   string
	constant string
}

type processBoundaryScan struct {
	calls       map[processBoundaryKey]int
	references  map[processBoundaryKey]int
	rawSyscalls map[rawSyscallBoundaryKey]int
	exports     map[string]int
	violations  []string
}

var guardedWorkerProcessAPI = map[string]struct{}{
	"NewControlWorkerSupervisor":        {},
	"IsControlWorkerChild":              {},
	"AcceptControlWorkerChild":          {},
	"BuildControlWorkerSnapshot":        {},
	"ReportControlWorkerReady":          {},
	"ExitControlWorkerFatal":            {},
	"CloseControlWorkerChild":           {},
	"IsControlWorkerSourceLoaderChild":  {},
	"RunControlWorkerSourceLoaderChild": {},
}

var guardedWorkerProcessInternals = map[string]struct{}{
	"defaultSupervisorSettings":                   {},
	"newControlWorkerSupervisor":                  {},
	"runControlWorkerSupervisor":                  {},
	"acceptControlWorkerChild":                    {},
	"newChildStatus":                              {},
	"buildControlWorkerCommand":                   {},
	"buildSourceLoaderCommand":                    {},
	"loadControlWorkerSourceFromCommand":          {},
	"loadControlWorkerSourceFromCommandUnchecked": {},
	"startControlWorker":                          {},
	"writeStatusByte":                             {},
}

var expectedProcessBoundaryCalls = map[processBoundaryKey]int{
	{file: "cmd/worker/main.go", source: workerProcessImport, symbol: "NewControlWorkerSupervisor"}:                                    1,
	{file: "cmd/worker/main.go", source: workerProcessImport, symbol: "IsControlWorkerChild"}:                                          1,
	{file: "cmd/worker/main.go", source: workerProcessImport, symbol: "AcceptControlWorkerChild"}:                                      1,
	{file: "cmd/worker/main.go", source: workerProcessImport, symbol: "IsControlWorkerSourceLoaderChild"}:                              1,
	{file: "cmd/worker/main.go", source: workerProcessImport, symbol: "RunControlWorkerSourceLoaderChild"}:                             1,
	{file: "cmd/worker/control_child.go", source: workerProcessImport, symbol: "ReportControlWorkerReady"}:                             1,
	{file: "cmd/worker/control_child.go", source: workerProcessImport, symbol: "ExitControlWorkerFatal"}:                               1,
	{file: "cmd/worker/control_child.go", source: workerProcessImport, symbol: "BuildControlWorkerSnapshot"}:                           1,
	{file: "cmd/worker/control_child.go", source: workerProcessImport, symbol: "CloseControlWorkerChild"}:                              2,
	{file: "internal/workerprocess/supervisor.go", source: "workerprocess", symbol: "defaultSupervisorSettings"}:                       1,
	{file: "internal/workerprocess/supervisor.go", source: "workerprocess", symbol: "newControlWorkerSupervisor"}:                      1,
	{file: "internal/workerprocess/supervisor.go", source: "workerprocess", symbol: "runControlWorkerSupervisor"}:                      1,
	{file: "internal/workerprocess/protocol.go", source: "workerprocess", symbol: "acceptControlWorkerChild"}:                          1,
	{file: "internal/workerprocess/protocol.go", source: workerProcessImport, symbol: "IsControlWorkerChild"}:                          1,
	{file: "internal/workerprocess/protocol.go", source: workerProcessImport, symbol: "IsControlWorkerSourceLoaderChild"}:              1,
	{file: "internal/workerprocess/platform_linux.go", source: "workerprocess", symbol: "newChildStatus"}:                              1,
	{file: "internal/workerprocess/platform_linux.go", source: "workerprocess", symbol: "buildControlWorkerCommand"}:                   1,
	{file: "internal/workerprocess/platform_linux.go", source: "workerprocess", symbol: "buildSourceLoaderCommand"}:                    1,
	{file: "internal/workerprocess/platform_linux.go", source: "workerprocess", symbol: "loadControlWorkerSourceFromCommand"}:          1,
	{file: "internal/workerprocess/platform_linux.go", source: "workerprocess", symbol: "loadControlWorkerSourceFromCommandUnchecked"}: 1,
	{file: "internal/workerprocess/platform_linux.go", source: "workerprocess", symbol: "startControlWorker"}:                          1,
	{file: "internal/workerprocess/protocol.go", source: "workerprocess", symbol: "writeStatusByte"}:                                   2,
	{file: "internal/workerprocess/platform_linux.go", source: "os/exec", symbol: "Command"}:                                           2,
}

var expectedWorkerProcessExports = map[string]int{
	"type:ControlWorkerSupervisor":           1,
	"type:ChildStatus":                       1,
	"func:NewControlWorkerSupervisor":        1,
	"func:IsControlWorkerChild":              1,
	"func:AcceptControlWorkerChild":          1,
	"func:BuildControlWorkerSnapshot":        1,
	"func:ReportControlWorkerReady":          1,
	"func:ExitControlWorkerFatal":            1,
	"func:CloseControlWorkerChild":           1,
	"func:IsControlWorkerSourceLoaderChild":  1,
	"func:RunControlWorkerSourceLoaderChild": 1,
	"method:ControlWorkerSupervisor.Run":     1,
	"method:boundedDiscard.Write":            1,
}

var expectedRawExecReferences = map[processBoundaryKey]int{
	{file: "internal/workerbootstrap/handoff_linux.go", source: "os/exec", symbol: "Cmd"}: 2,
	{file: "internal/workerbootstrap/handoff_other.go", source: "os/exec", symbol: "Cmd"}: 1,
	{file: "internal/workerprocess/platform_linux.go", source: "os/exec", symbol: "Cmd"}:  12,
	{file: "internal/workerprocess/supervisor.go", source: "os/exec", symbol: "Cmd"}:      1,
}

var expectedWorkerProcessSignalReferences = map[processBoundaryKey]int{
	{file: "internal/workerprocess/platform_linux.go", source: "syscall", symbol: "SIGTERM"}: 1,
}

var expectedRawSyscalls = map[rawSyscallBoundaryKey]int{
	{file: "internal/runnerclient/files.go", source: "syscall", symbol: "Syscall6", constant: "syscall.SYS_FLISTXATTR"}:                    2,
	{file: "internal/runnerclient/files.go", source: "syscall", symbol: "Syscall6", constant: "darwinFgetattrlistSyscall=228"}:             1,
	{file: "internal/readrunnerclient/files.go", source: "syscall", symbol: "Syscall6", constant: "syscall.SYS_FLISTXATTR"}:                2,
	{file: "internal/readrunnerclient/files.go", source: "syscall", symbol: "Syscall6", constant: "darwinFgetattrlistSyscall=228"}:         1,
	{file: "internal/runneridentity/files.go", source: "syscall", symbol: "Syscall6", constant: "syscall.SYS_FLISTXATTR"}:                  2,
	{file: "internal/runneridentity/files.go", source: "syscall", symbol: "Syscall6", constant: "darwinFgetattrlistSyscall=228"}:           1,
	{file: "internal/credential/keyring_file.go", source: "syscall", symbol: "Syscall6", constant: "syscall.SYS_FLISTXATTR"}:               2,
	{file: "internal/credential/keyring_file.go", source: "syscall", symbol: "Syscall6", constant: "darwinFgetattrlistSyscall=228"}:        1,
	{file: "internal/securemanifest/file_supported.go", source: "syscall", symbol: "Syscall6", constant: "syscall.SYS_FLISTXATTR"}:         2,
	{file: "internal/securemanifest/file_supported.go", source: "syscall", symbol: "Syscall6", constant: "darwinFgetattrlistSyscall=228"}:  1,
	{file: "internal/processsecurity/security_linux.go", source: "syscall", symbol: "Syscall6", constant: "syscall.SYS_PRCTL"}:             2,
	{file: "internal/workerprocess/platform_linux.go", source: "syscall", symbol: "Syscall6", constant: "golang.org/x/sys/unix.SYS_PRCTL"}: 1,
}

var rawExecImportAllowlist = map[string]struct{}{
	"internal/workerbootstrap/handoff_linux.go":       {},
	"internal/workerbootstrap/handoff_other.go":       {},
	"internal/workerprocess/platform_linux.go":        {},
	"internal/workerprocess/supervisor.go":            {},
	"internal/isolatedexec/platform_linux.go":         {},
	"internal/isolatedexec/platform_other.go":         {},
	"internal/isolatedexec/process.go":                {},
	"internal/isolatedexec/testdata/executor/main.go": {},
}

var workerProcessImportAllowlist = map[string]struct{}{
	"cmd/worker/main.go":          {},
	"cmd/worker/control_child.go": {},
}

var processEscapeSymbols = map[string]struct{}{
	"Clone":   {},
	"Setpgid": {},
	"Setns":   {},
	"Setsid":  {},
	"Unshare": {},
}

var rawProcessConstants = map[string]struct{}{
	"SYS_CLONE":    {},
	"SYS_CLONE3":   {},
	"SYS_EXECVE":   {},
	"SYS_EXECVEAT": {},
	"SYS_FORK":     {},
	"SYS_SETNS":    {},
	"SYS_SETPGID":  {},
	"SYS_SETSID":   {},
	"SYS_UNSHARE":  {},
	"SYS_VFORK":    {},
}

var sysProcAttrEscapeFields = map[string]struct{}{
	"Cloneflags":   {},
	"Setsid":       {},
	"Unshareflags": {},
}

func TestControlWorkerProcessAssemblyCallsitesAreClosed(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate process-boundary architecture test")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../.."))
	scan, err := scanProcessBoundary(repositoryRoot)
	if err != nil {
		t.Fatalf("scan production Go files: %v", err)
	}
	for _, violation := range validateProcessBoundary(scan) {
		t.Error(violation)
	}
}

func TestSemanticSnapshotReadyProofHasOneProductionWrite(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate process-boundary architecture test")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../.."))
	writes, err := scanSnapshotProofWrites(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"internal/workerprocess/protocol.go": 1}
	if !sameProcessStringCounts(writes, want) {
		t.Fatalf("snapshotBuilt production writes = %#v, want %#v", writes, want)
	}

	fixtureRoot := t.TempDir()
	writeProcessBoundaryFixture(t, fixtureRoot, "internal/workerprocess/bypass.go", `package workerprocess

func bypassSnapshotProof(status *ChildStatus) {
	status.snapshotBuilt = true
	_ = ChildStatus{nil, nil, nil, 0, true, nil, nil}
}
`)
	fixtureWrites, err := scanSnapshotProofWrites(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	if sameProcessStringCounts(fixtureWrites, want) || fixtureWrites["internal/workerprocess/bypass.go"] < 2 {
		t.Fatalf("snapshot proof scanner accepted bypass: %#v", fixtureWrites)
	}
}

func scanSnapshotProofWrites(repositoryRoot string) (map[string]int, error) {
	writes := make(map[string]int)
	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(repositoryRoot, path)
		if err != nil {
			return err
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.AssignStmt:
				for _, expression := range typed.Lhs {
					selector, ok := expression.(*ast.SelectorExpr)
					if ok && selector.Sel.Name == "snapshotBuilt" {
						writes[relative]++
					}
				}
			case *ast.KeyValueExpr:
				if identifier, ok := typed.Key.(*ast.Ident); ok && identifier.Name == "snapshotBuilt" {
					writes[relative]++
				}
			case *ast.CompositeLit:
				identifier, ok := typed.Type.(*ast.Ident)
				if !ok || identifier.Name != "ChildStatus" || len(typed.Elts) == 0 {
					return true
				}
				for _, element := range typed.Elts {
					if _, keyed := element.(*ast.KeyValueExpr); !keyed {
						writes[relative]++
						break
					}
				}
			}
			return true
		})
		return nil
	})
	return writes, err
}

func sameProcessStringCounts(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range right {
		if left[key] != value {
			return false
		}
	}
	return true
}

func TestProcessBoundaryScannerRejectsAliasesAndAlternateExec(t *testing.T) {
	root := t.TempDir()
	writeProcessBoundaryFixture(t, root, "cmd/worker/main.go", `package main

import (
	worker "github.com/seaworld008/aiops-system/internal/workerprocess"
	xsys "golang.org/x/sys/unix"
	proc "os"
	"os/exec"
	sys "syscall"
)

type aliasedSysProcAttr = sys.SysProcAttr
type namedSysProcAttr sys.SysProcAttr

func bypass(status *worker.ChildStatus) {
	ctor := worker.NewControlWorkerSupervisor
	ctor()
	_ = worker.AcceptControlWorkerChild
	worker.ReportControlWorkerReady(status)
	worker.ExitControlWorkerFatal(status)
	exec.CommandContext(nil, "sh")
	sys.Setsid()
	escape := sys.Setpgid
	_ = escape
	xsys.Clone()
	xsys.Unshare(0)
	setns := xsys.Setns
	_ = setns
	_ = &sys.SysProcAttr{Setsid: true, Cloneflags: xsys.CLONE_NEWNS, Unshareflags: xsys.CLONE_NEWNS}
	attributes := &sys.SysProcAttr{}
	attributes.Setsid = true
	attributes.Cloneflags = xsys.CLONE_NEWNS
	attributes.Unshareflags |= xsys.CLONE_NEWNS
	_ = sys.SysProcAttr{"escape"}
	_ = &aliasedSysProcAttr{Setsid: true}
	_ = &namedSysProcAttr{Cloneflags: xsys.CLONE_NEWNS}
	_ = namedSysProcAttr{"escape"}
	spawn := proc.StartProcess
	_ = spawn
	fork := xsys.ForkExec
	_ = fork
	execve := sys.Exec
	_ = execve
	_ = sys.SYS_FORK
	_ = sys.SYS_VFORK
	_ = sys.SYS_CLONE
	_ = xsys.SYS_CLONE3
	_ = sys.SYS_EXECVE
	_ = xsys.SYS_EXECVEAT
	_ = sys.SYS_SETSID
	_ = sys.SYS_SETPGID
	_ = xsys.SYS_UNSHARE
	_ = xsys.SYS_SETNS
	_ = sys.RawSyscall
}
`)
	writeProcessBoundaryFixture(t, root, "internal/workerprocess/platform_linux.go", `package workerprocess

import process "os/exec"

func bypass() {
	create := process.Command
	create("sh")
	_ = newControlWorkerSupervisor
}

func NewSupervisorWithEnv() {}
`)
	writeProcessBoundaryFixture(t, root, "internal/rogue/dot.go", `package rogue

import . "golang.org/x/sys/unix"

func bypass() {
	Setsid()
	_ = SYS_CLONE
}
`)

	scan, err := scanProcessBoundary(root)
	if err != nil {
		t.Fatalf("scan violation fixture: %v", err)
	}
	violations := strings.Join(validateProcessBoundary(scan), "\n")
	for _, expected := range []string{
		"references workerprocess.NewControlWorkerSupervisor as a value",
		"references workerprocess.AcceptControlWorkerChild as a value",
		"invokes unreviewed workerprocess.ReportControlWorkerReady",
		"invokes unreviewed workerprocess.ExitControlWorkerFatal",
		"references os/exec.Command as a value",
		"references unqualified newControlWorkerSupervisor as a value",
		"uses unreviewed os/exec selector CommandContext",
		"uses unreviewed os.StartProcess",
		"uses unreviewed process primitive golang.org/x/sys/unix.ForkExec",
		"uses unreviewed process primitive syscall.Exec",
		"dot-imports guarded process capability golang.org/x/sys/unix",
		"uses unreviewed process escape syscall.Setsid",
		"references unreviewed process escape syscall.Setpgid as a value",
		"uses unreviewed process escape golang.org/x/sys/unix.Clone",
		"uses unreviewed process escape golang.org/x/sys/unix.Unshare",
		"references unreviewed process escape golang.org/x/sys/unix.Setns as a value",
		"configures unreviewed process escape syscall.SysProcAttr.Setsid",
		"configures unreviewed process escape syscall.SysProcAttr.Cloneflags",
		"configures unreviewed process escape syscall.SysProcAttr.Unshareflags",
		"assigns unreviewed process escape field .Setsid",
		"assigns unreviewed process escape field .Cloneflags",
		"assigns unreviewed process escape field .Unshareflags",
		"uses positional syscall.SysProcAttr literal",
		"declares unreviewed syscall.SysProcAttr alias aliasedSysProcAttr",
		"declares unreviewed syscall.SysProcAttr derived type namedSysProcAttr",
		"configures unreviewed process escape syscall.SysProcAttr.Setsid through aliasedSysProcAttr",
		"configures unreviewed process escape syscall.SysProcAttr.Cloneflags through namedSysProcAttr",
		"uses positional syscall.SysProcAttr literal through namedSysProcAttr",
		"references unreviewed raw process constant syscall.SYS_FORK",
		"references unreviewed raw process constant syscall.SYS_VFORK",
		"references unreviewed raw process constant syscall.SYS_CLONE",
		"references unreviewed raw process constant golang.org/x/sys/unix.SYS_CLONE3",
		"references unreviewed raw process constant syscall.SYS_EXECVE",
		"references unreviewed raw process constant golang.org/x/sys/unix.SYS_EXECVEAT",
		"references unreviewed raw process constant syscall.SYS_SETSID",
		"references unreviewed raw process constant syscall.SYS_SETPGID",
		"references unreviewed raw process constant golang.org/x/sys/unix.SYS_UNSHARE",
		"references unreviewed raw process constant golang.org/x/sys/unix.SYS_SETNS",
		"references unreviewed raw syscall syscall.RawSyscall as a value",
		"exports unreviewed func:NewSupervisorWithEnv",
	} {
		if !strings.Contains(violations, expected) {
			t.Errorf("scanner violations do not contain %q; got:\n%s", expected, violations)
		}
	}
}

func TestProcessBoundaryScannerAllowsReviewedGroupSignalAndPrctlBoundary(t *testing.T) {
	root := t.TempDir()
	writeProcessBoundaryFixture(t, root, "internal/workerprocess/platform_linux.go", `package workerprocess

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func reviewed(command *exec.Cmd, pid int) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_, _, _ = syscall.Syscall6(unix.SYS_PRCTL, unix.PR_GET_PDEATHSIG, 0, 0, 0, 0, 0)
}
`)
	writeProcessBoundaryFixture(t, root, "internal/isolatedexec/platform_linux.go", `package isolatedexec

import (
	"os/exec"
	"syscall"
)

func reviewed(command *exec.Cmd, pid int) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
`)
	writeProcessBoundaryFixture(t, root, "cmd/worker/control_child.go", `package main

import worker "github.com/seaworld008/aiops-system/internal/workerprocess"

type childStatus = worker.ChildStatus
`)

	scan, err := scanProcessBoundary(root)
	if err != nil {
		t.Fatalf("scan reviewed process fixture: %v", err)
	}
	if len(scan.violations) != 0 {
		t.Fatalf("reviewed process boundary was rejected:\n%s", strings.Join(scan.violations, "\n"))
	}
}

func TestProcessBoundaryScannerRejectsUnreviewedRawSyscallsRepositoryWide(t *testing.T) {
	root := t.TempDir()
	writeProcessBoundaryFixture(t, root, "internal/rogue/raw.go", `package rogue

import sys "syscall"

const almostDarwinFgetattrlist = 229

func bypass(number uintptr) {
	_, _, _ = sys.Syscall6(56, 0, 0, 0, 0, 0, 0)
	_, _, _ = sys.RawSyscall(number, 0, 0)
	_, _, _ = sys.Syscall(sys.SYS_FLISTXATTR, 0, 0, 0)
	_, _, _ = sys.Syscall6(almostDarwinFgetattrlist, 0, 0, 0, 0, 0, 0)
	_, _, _ = sys.AllThreadsSyscall(56, 0, 0, 0)
	_, _, _ = sys.AllThreadsSyscall6(number, 0, 0, 0, 0, 0, 0)
	_, _, _ = sys.AllThreadsSyscall(sys.SYS_FLISTXATTR, 0, 0, 0)
	_, _, _ = sys.AllThreadsRawSyscall6(number, 0, 0, 0, 0, 0, 0)
	raw := sys.Syscall6
	_ = raw
	allThreadsRaw := sys.AllThreadsRawSyscall
	_ = allThreadsRaw
	_ = sys.SYS_CLONE
}
`)

	scan, err := scanProcessBoundary(root)
	if err != nil {
		t.Fatalf("scan raw syscall fixture: %v", err)
	}
	violations := strings.Join(scan.violations, "\n")
	for _, expected := range []string{
		"production file internal/rogue/raw.go invokes raw syscall syscall.Syscall6 with a literal number",
		"production file internal/rogue/raw.go invokes raw syscall syscall.RawSyscall with a syscall number that is not an exact reviewed constant",
		"production file internal/rogue/raw.go invokes unreviewed raw syscall syscall.Syscall for syscall.SYS_FLISTXATTR",
		"production file internal/rogue/raw.go invokes unreviewed raw syscall syscall.Syscall6 for almostDarwinFgetattrlist=229",
		"production file internal/rogue/raw.go invokes raw syscall syscall.AllThreadsSyscall with a literal number",
		"production file internal/rogue/raw.go invokes raw syscall syscall.AllThreadsSyscall6 with a syscall number that is not an exact reviewed constant",
		"production file internal/rogue/raw.go invokes unreviewed raw syscall syscall.AllThreadsSyscall for syscall.SYS_FLISTXATTR",
		"production file internal/rogue/raw.go invokes raw syscall syscall.AllThreadsRawSyscall6 with a syscall number that is not an exact reviewed constant",
		"production file internal/rogue/raw.go references unreviewed raw syscall syscall.Syscall6 as a value",
		"production file internal/rogue/raw.go references unreviewed raw syscall syscall.AllThreadsRawSyscall as a value",
		"production file internal/rogue/raw.go references unreviewed raw process constant syscall.SYS_CLONE",
	} {
		if !strings.Contains(violations, expected) {
			t.Errorf("scanner violations do not contain %q; got:\n%s", expected, violations)
		}
	}
}

func TestProcessBoundaryScannerRejectsSecondWorkerSIGTERMReference(t *testing.T) {
	root := t.TempDir()
	writeProcessBoundaryFixture(t, root, "internal/workerprocess/platform_linux.go", `package workerprocess

import sys "syscall"

func terminateTwice() {
	_ = sys.Kill(1, sys.SIGTERM)
	_ = sys.Kill(2, sys.SIGTERM)
}
`)

	scan, err := scanProcessBoundary(root)
	if err != nil {
		t.Fatalf("scan SIGTERM fixture: %v", err)
	}
	violations := strings.Join(validateProcessBoundary(scan), "\n")
	if expected := "guarded workerprocess signal reference syscall.SIGTERM in internal/workerprocess/platform_linux.go has 2 references, want exactly 1"; !strings.Contains(violations, expected) {
		t.Fatalf("scanner violations do not contain %q; got:\n%s", expected, violations)
	}
}

func scanWorkerProcessExports(scan *processBoundaryScan, relative string, parsed *ast.File) {
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			if typed.Name == nil || !ast.IsExported(typed.Name.Name) {
				continue
			}
			key := "func:" + typed.Name.Name
			if typed.Recv != nil && len(typed.Recv.List) == 1 {
				receiver := processReceiverName(typed.Recv.List[0].Type)
				key = "method:" + receiver + "." + typed.Name.Name
			}
			scan.exports[key]++
		case *ast.GenDecl:
			for _, specification := range typed.Specs {
				switch spec := specification.(type) {
				case *ast.TypeSpec:
					if ast.IsExported(spec.Name.Name) {
						scan.exports["type:"+spec.Name.Name]++
					}
					if structure, ok := spec.Type.(*ast.StructType); ok {
						for _, field := range structure.Fields.List {
							if len(field.Names) == 0 {
								if embedded := processReceiverName(field.Type); ast.IsExported(embedded) {
									scan.violations = append(scan.violations, fmt.Sprintf(
										"production file %s exports embedded field %s", relative, embedded))
								}
								continue
							}
							for _, name := range field.Names {
								if ast.IsExported(name.Name) {
									scan.violations = append(scan.violations, fmt.Sprintf(
										"production file %s exports struct field %s.%s",
										relative, spec.Name.Name, name.Name))
								}
							}
						}
					}
				case *ast.ValueSpec:
					for _, name := range spec.Names {
						if ast.IsExported(name.Name) {
							scan.exports["value:"+name.Name]++
						}
					}
				}
			}
		}
	}
}

func processReceiverName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return processReceiverName(typed.X)
	case *ast.IndexExpr:
		return processReceiverName(typed.X)
	case *ast.IndexListExpr:
		return processReceiverName(typed.X)
	default:
		return "<unknown>"
	}
}

func writeProcessBoundaryFixture(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func scanProcessBoundary(repositoryRoot string) (processBoundaryScan, error) {
	scan := processBoundaryScan{
		calls:       make(map[processBoundaryKey]int),
		references:  make(map[processBoundaryKey]int),
		rawSyscalls: make(map[rawSyscallBoundaryKey]int),
		exports:     make(map[string]int),
	}
	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != repositoryRoot && (strings.HasPrefix(entry.Name(), ".") ||
				entry.Name() == "vendor" || entry.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(repositoryRoot, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		inWorkerBoundary := strings.HasPrefix(relative, "cmd/worker/") ||
			strings.HasPrefix(relative, "internal/workerprocess/") ||
			strings.HasPrefix(relative, "internal/workerbootstrap/handoff_")
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}

		aliases := make(map[string]string)
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			alias := filepath.Base(importPath)
			if imported.Name != nil {
				alias = imported.Name.Name
			}
			if importPath == workerProcessImport {
				if _, allowed := workerProcessImportAllowlist[relative]; !allowed {
					scan.violations = append(scan.violations, fmt.Sprintf(
						"production file %s imports workerprocess outside the reviewed cmd/worker assembly", relative))
				}
			}
			if importPath == "os/exec" {
				if _, allowed := rawExecImportAllowlist[relative]; !allowed {
					scan.violations = append(scan.violations, fmt.Sprintf(
						"production file %s imports raw os/exec outside the reviewed process boundaries", relative))
				}
			}
			if alias == "." && (importPath == workerProcessImport || importPath == "os/exec") {
				scan.violations = append(scan.violations, fmt.Sprintf(
					"production file %s dot-imports guarded process capability %s", relative, importPath))
				continue
			}
			if alias == "." && (importPath == "os" || importPath == "syscall" ||
				importPath == "golang.org/x/sys/unix") {
				scan.violations = append(scan.violations, fmt.Sprintf(
					"production file %s dot-imports guarded process capability %s", relative, importPath))
				continue
			}
			if alias != "_" {
				aliases[alias] = importPath
			}
		}

		samePackage := parsed.Name != nil && parsed.Name.Name == "workerprocess"
		if samePackage {
			scanWorkerProcessExports(&scan, relative, parsed)
		}
		inspectProcessBoundary(parsed, func(node, parent ast.Node) {
			switch syntax := node.(type) {
			case *ast.AssignStmt:
				for _, target := range syntax.Lhs {
					scanSysProcAttrEscapeAssignment(&scan, relative, target)
				}
			case *ast.IncDecStmt:
				scanSysProcAttrEscapeAssignment(&scan, relative, syntax.X)
			case *ast.CompositeLit:
				scanPositionalSysProcAttr(&scan, relative, aliases, syntax)
			case *ast.KeyValueExpr:
				scanSysProcAttrEscapeField(&scan, relative, aliases, syntax, parent)
			case *ast.TypeSpec:
				scanSysProcAttrTypeDefinition(&scan, relative, aliases, syntax)
			case *ast.Ident:
				if !samePackage {
					return
				}
				_, guardedInternal := guardedWorkerProcessInternals[syntax.Name]
				_, guardedExport := guardedWorkerProcessAPI[syntax.Name]
				if !guardedInternal && !guardedExport {
					return
				}
				if declaration, ok := parent.(*ast.FuncDecl); ok && declaration.Name == syntax {
					return
				}
				source := "workerprocess"
				if guardedExport {
					source = workerProcessImport
				}
				key := processBoundaryKey{file: relative, source: source, symbol: syntax.Name}
				if isDirectProcessBoundaryCall(parent, syntax) {
					scan.calls[key]++
					if _, expected := expectedProcessBoundaryCalls[key]; !expected {
						scan.violations = append(scan.violations, fmt.Sprintf(
							"production file %s invokes unreviewed unqualified %s", relative, syntax.Name))
					}
					return
				}
				scan.violations = append(scan.violations, fmt.Sprintf(
					"production file %s references unqualified %s as a value", relative, syntax.Name))
			case *ast.SelectorExpr:
				qualifier, ok := syntax.X.(*ast.Ident)
				if ok {
					importPath := aliases[qualifier.Name]
					switch importPath {
					case workerProcessImport:
						scanGuardedPackageCall(&scan, relative, workerProcessImport, syntax, parent)
					case "os/exec":
						if inWorkerBoundary {
							scanRawExecReference(&scan, relative, syntax, parent)
						}
					case "os":
						if syntax.Sel.Name == "StartProcess" {
							scan.violations = append(scan.violations, fmt.Sprintf(
								"production file %s uses unreviewed os.StartProcess", relative))
						}
					case "syscall", "golang.org/x/sys/unix":
						if isRawProcessSyscall(syntax.Sel.Name) {
							scanRawProcessSyscall(&scan, relative, importPath, aliases, syntax, parent)
						}
						if syntax.Sel.Name == "SIGTERM" && strings.HasPrefix(relative, "internal/workerprocess/") {
							scanWorkerProcessSIGTERM(&scan, relative, importPath, syntax, parent)
						}
						if _, guarded := processEscapeSymbols[syntax.Sel.Name]; guarded {
							scanProcessEscape(&scan, relative, importPath, syntax, parent)
						}
						if _, guarded := rawProcessConstants[syntax.Sel.Name]; guarded {
							scan.violations = append(scan.violations, fmt.Sprintf(
								"production file %s references unreviewed raw process constant %s.%s",
								relative, importPath, syntax.Sel.Name))
						}
						if syntax.Sel.Name == "ForkExec" || syntax.Sel.Name == "Exec" || syntax.Sel.Name == "StartProcess" {
							scan.violations = append(scan.violations, fmt.Sprintf(
								"production file %s uses unreviewed process primitive %s.%s",
								relative, importPath, syntax.Sel.Name))
						}
					}
				}
			}
		})
		return nil
	})
	return scan, err
}

func scanSysProcAttrTypeDefinition(
	scan *processBoundaryScan,
	relative string,
	aliases map[string]string,
	definition *ast.TypeSpec,
) {
	importPath, _, ok := resolveSysProcAttrType(definition.Type, aliases, nil)
	if !ok {
		return
	}
	kind := "derived type"
	if definition.Assign.IsValid() {
		kind = "alias"
	}
	scan.violations = append(scan.violations, fmt.Sprintf(
		"production file %s declares unreviewed %s.SysProcAttr %s %s",
		relative, importPath, kind, definition.Name.Name))
}

func resolveSysProcAttrType(
	expression ast.Expr,
	aliases map[string]string,
	visited map[*ast.TypeSpec]struct{},
) (importPath, through string, ok bool) {
	switch typed := expression.(type) {
	case *ast.ParenExpr:
		return resolveSysProcAttrType(typed.X, aliases, visited)
	case *ast.StarExpr:
		return resolveSysProcAttrType(typed.X, aliases, visited)
	case *ast.SelectorExpr:
		qualifier, ok := typed.X.(*ast.Ident)
		if !ok || typed.Sel.Name != "SysProcAttr" {
			return "", "", false
		}
		importPath := aliases[qualifier.Name]
		if importPath != "syscall" && importPath != "golang.org/x/sys/unix" {
			return "", "", false
		}
		return importPath, "", true
	case *ast.Ident:
		if typed.Obj == nil || typed.Obj.Kind != ast.Typ {
			return "", "", false
		}
		definition, ok := typed.Obj.Decl.(*ast.TypeSpec)
		if !ok {
			return "", "", false
		}
		if visited == nil {
			visited = make(map[*ast.TypeSpec]struct{})
		}
		if _, seen := visited[definition]; seen {
			return "", "", false
		}
		visited[definition] = struct{}{}
		importPath, _, ok := resolveSysProcAttrType(definition.Type, aliases, visited)
		if !ok {
			return "", "", false
		}
		return importPath, typed.Name, true
	default:
		return "", "", false
	}
}

func scanSysProcAttrEscapeAssignment(scan *processBoundaryScan, relative string, expression ast.Expr) {
	for {
		switch typed := expression.(type) {
		case *ast.ParenExpr:
			expression = typed.X
		case *ast.StarExpr:
			expression = typed.X
		default:
			selector, ok := expression.(*ast.SelectorExpr)
			if !ok {
				return
			}
			if _, guarded := sysProcAttrEscapeFields[selector.Sel.Name]; !guarded {
				return
			}
			scan.violations = append(scan.violations, fmt.Sprintf(
				"production file %s assigns unreviewed process escape field .%s",
				relative, selector.Sel.Name))
			return
		}
	}
}

func scanPositionalSysProcAttr(
	scan *processBoundaryScan,
	relative string,
	aliases map[string]string,
	literal *ast.CompositeLit,
) {
	importPath, through, ok := resolveSysProcAttrType(literal.Type, aliases, nil)
	if !ok {
		return
	}
	suffix := ""
	if through != "" {
		suffix = " through " + through
	}
	for _, element := range literal.Elts {
		if _, keyed := element.(*ast.KeyValueExpr); keyed {
			continue
		}
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s uses positional %s.SysProcAttr literal%s", relative, importPath, suffix))
		return
	}
}

func scanSysProcAttrEscapeField(
	scan *processBoundaryScan,
	relative string,
	aliases map[string]string,
	field *ast.KeyValueExpr,
	parent ast.Node,
) {
	name, ok := field.Key.(*ast.Ident)
	if !ok {
		return
	}
	if _, guarded := sysProcAttrEscapeFields[name.Name]; !guarded {
		return
	}
	literal, ok := parent.(*ast.CompositeLit)
	if !ok {
		return
	}
	importPath, through, ok := resolveSysProcAttrType(literal.Type, aliases, nil)
	if !ok {
		return
	}
	suffix := ""
	if through != "" {
		suffix = " through " + through
	}
	scan.violations = append(scan.violations, fmt.Sprintf(
		"production file %s configures unreviewed process escape %s.SysProcAttr.%s%s",
		relative, importPath, name.Name, suffix))
}

func scanProcessEscape(
	scan *processBoundaryScan,
	relative string,
	importPath string,
	syntax *ast.SelectorExpr,
	parent ast.Node,
) {
	if isDirectProcessBoundaryCall(parent, syntax) {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s uses unreviewed process escape %s.%s",
			relative, importPath, syntax.Sel.Name))
		return
	}
	scan.violations = append(scan.violations, fmt.Sprintf(
		"production file %s references unreviewed process escape %s.%s as a value",
		relative, importPath, syntax.Sel.Name))
}

func isRawProcessSyscall(symbol string) bool {
	trimmed := strings.TrimPrefix(symbol, "AllThreads")
	return strings.HasPrefix(trimmed, "Syscall") || strings.HasPrefix(trimmed, "RawSyscall")
}

func scanRawProcessSyscall(
	scan *processBoundaryScan,
	relative string,
	importPath string,
	aliases map[string]string,
	syntax *ast.SelectorExpr,
	parent ast.Node,
) {
	call, direct := parent.(*ast.CallExpr)
	if !direct || call.Fun != syntax {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s references unreviewed raw syscall %s.%s as a value",
			relative, importPath, syntax.Sel.Name))
		return
	}
	if len(call.Args) == 0 {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s invokes raw syscall %s.%s with a syscall number that is not an exact reviewed constant",
			relative, importPath, syntax.Sel.Name))
		return
	}
	constant, literal, ok := rawSyscallConstant(call.Args[0], aliases)
	if literal {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s invokes raw syscall %s.%s with a literal number",
			relative, importPath, syntax.Sel.Name))
		return
	}
	if !ok {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s invokes raw syscall %s.%s with a syscall number that is not an exact reviewed constant",
			relative, importPath, syntax.Sel.Name))
		return
	}
	key := rawSyscallBoundaryKey{
		file:     relative,
		source:   importPath,
		symbol:   syntax.Sel.Name,
		constant: constant,
	}
	scan.rawSyscalls[key]++
	if _, expected := expectedRawSyscalls[key]; !expected {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s invokes unreviewed raw syscall %s.%s for %s",
			relative, importPath, syntax.Sel.Name, constant))
	}
}

func rawSyscallConstant(expression ast.Expr, aliases map[string]string) (constant string, literal, ok bool) {
	switch typed := expression.(type) {
	case *ast.ParenExpr:
		return rawSyscallConstant(typed.X, aliases)
	case *ast.BasicLit:
		return "", typed.Kind == token.INT, false
	case *ast.SelectorExpr:
		qualifier, ok := typed.X.(*ast.Ident)
		if !ok {
			return "", false, false
		}
		importPath := aliases[qualifier.Name]
		if importPath != "syscall" && importPath != "golang.org/x/sys/unix" {
			return "", false, false
		}
		return importPath + "." + typed.Sel.Name, false, true
	case *ast.Ident:
		value, ok := integerConstantValue(typed)
		if !ok {
			return "", false, false
		}
		return typed.Name + "=" + value, false, true
	default:
		return "", false, false
	}
}

func integerConstantValue(identifier *ast.Ident) (string, bool) {
	if identifier.Obj == nil || identifier.Obj.Kind != ast.Con {
		return "", false
	}
	specification, ok := identifier.Obj.Decl.(*ast.ValueSpec)
	if !ok {
		return "", false
	}
	valueIndex := -1
	for index, name := range specification.Names {
		if name.Name == identifier.Name {
			valueIndex = index
			break
		}
	}
	if valueIndex < 0 || valueIndex >= len(specification.Values) {
		return "", false
	}
	literal, ok := specification.Values[valueIndex].(*ast.BasicLit)
	if !ok || literal.Kind != token.INT {
		return "", false
	}
	value, err := strconv.ParseUint(strings.ReplaceAll(literal.Value, "_", ""), 0, 64)
	if err != nil {
		return "", false
	}
	return strconv.FormatUint(value, 10), true
}

func scanWorkerProcessSIGTERM(
	scan *processBoundaryScan,
	relative string,
	importPath string,
	syntax *ast.SelectorExpr,
	parent ast.Node,
) {
	key := processBoundaryKey{file: relative, source: importPath, symbol: syntax.Sel.Name}
	scan.references[key]++
	if _, expected := expectedWorkerProcessSignalReferences[key]; !expected || !isReviewedWorkerTERMCall(parent, syntax) {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s uses SIGTERM outside the reviewed process.signalGroup callsite", relative))
	}
}

func isReviewedWorkerTERMCall(parent ast.Node, signal ast.Expr) bool {
	call, ok := parent.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || call.Args[0] != signal {
		return false
	}
	function, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || function.Sel.Name != "signalGroup" {
		return false
	}
	receiver, ok := function.X.(*ast.Ident)
	return ok && receiver.Name == "process"
}

func inspectProcessBoundary(root ast.Node, visit func(ast.Node, ast.Node)) {
	stack := make([]ast.Node, 0, 16)
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		var parent ast.Node
		if len(stack) != 0 {
			parent = stack[len(stack)-1]
		}
		visit(node, parent)
		stack = append(stack, node)
		return true
	})
}

func isDirectProcessBoundaryCall(parent ast.Node, function ast.Expr) bool {
	call, ok := parent.(*ast.CallExpr)
	return ok && call.Fun == function
}

func scanGuardedPackageCall(
	scan *processBoundaryScan,
	relative string,
	importPath string,
	syntax *ast.SelectorExpr,
	parent ast.Node,
) {
	if _, guarded := guardedWorkerProcessAPI[syntax.Sel.Name]; !guarded {
		return
	}
	key := processBoundaryKey{file: relative, source: importPath, symbol: syntax.Sel.Name}
	if !isDirectProcessBoundaryCall(parent, syntax) {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s references workerprocess.%s as a value", relative, syntax.Sel.Name))
		return
	}
	scan.calls[key]++
	if _, expected := expectedProcessBoundaryCalls[key]; !expected {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s invokes unreviewed workerprocess.%s", relative, syntax.Sel.Name))
	}
}

func scanRawExecReference(
	scan *processBoundaryScan,
	relative string,
	syntax *ast.SelectorExpr,
	parent ast.Node,
) {
	key := processBoundaryKey{file: relative, source: "os/exec", symbol: syntax.Sel.Name}
	switch syntax.Sel.Name {
	case "Command":
		if !isDirectProcessBoundaryCall(parent, syntax) {
			scan.violations = append(scan.violations, fmt.Sprintf(
				"production file %s references os/exec.Command as a value", relative))
			return
		}
		scan.calls[key]++
		if _, expected := expectedProcessBoundaryCalls[key]; !expected {
			scan.violations = append(scan.violations, fmt.Sprintf(
				"production file %s invokes unreviewed os/exec.Command", relative))
		}
	case "Cmd":
		scan.references[key]++
	default:
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s uses unreviewed os/exec selector %s", relative, syntax.Sel.Name))
	}
}

func validateProcessBoundary(scan processBoundaryScan) []string {
	violations := append([]string(nil), scan.violations...)
	for key, expected := range expectedProcessBoundaryCalls {
		if actual := scan.calls[key]; actual != expected {
			violations = append(violations, fmt.Sprintf(
				"guarded process call %s.%s in %s has %d callsites, want exactly %d",
				key.source, key.symbol, key.file, actual, expected))
		}
	}
	for key, expected := range expectedRawExecReferences {
		if actual := scan.references[key]; actual != expected {
			violations = append(violations, fmt.Sprintf(
				"guarded raw process reference %s.%s in %s has %d references, want exactly %d",
				key.source, key.symbol, key.file, actual, expected))
		}
	}
	for key, expected := range expectedWorkerProcessSignalReferences {
		if actual := scan.references[key]; actual != expected {
			violations = append(violations, fmt.Sprintf(
				"guarded workerprocess signal reference %s.%s in %s has %d references, want exactly %d",
				key.source, key.symbol, key.file, actual, expected))
		}
	}
	for key, expected := range expectedRawSyscalls {
		if actual := scan.rawSyscalls[key]; actual != expected {
			violations = append(violations, fmt.Sprintf(
				"reviewed raw syscall %s.%s for %s in %s has %d callsites, want exactly %d",
				key.source, key.symbol, key.constant, key.file, actual, expected))
		}
	}
	for key, actual := range scan.exports {
		if _, expected := expectedWorkerProcessExports[key]; !expected {
			violations = append(violations, fmt.Sprintf(
				"workerprocess exports unreviewed %s with %d declarations", key, actual))
		}
	}
	for key, expected := range expectedWorkerProcessExports {
		if actual := scan.exports[key]; actual != expected {
			violations = append(violations, fmt.Sprintf(
				"guarded workerprocess export %s has %d declarations, want exactly %d",
				key, actual, expected))
		}
	}
	sort.Strings(violations)
	return violations
}
