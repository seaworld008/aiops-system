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

	"github.com/seaworld008/aiops-system/internal/workerprocess"
)

const workerProcessImport = "github.com/seaworld008/aiops-system/internal/workerprocess"

var (
	_ func() *workerprocess.ControlWorkerSupervisor      = workerprocess.NewControlWorkerSupervisor
	_ func([]string) bool                                = workerprocess.IsControlWorkerChild
	_ func([]string) (*workerprocess.ChildStatus, error) = workerprocess.AcceptControlWorkerChild
	_ func(*workerprocess.ChildStatus) error             = workerprocess.ReportControlWorkerReady
	_ func(*workerprocess.ChildStatus)                   = workerprocess.ExitControlWorkerFatal
	_ func(*workerprocess.ChildStatus) error             = workerprocess.CloseControlWorkerChild
	_ interface{ Run(context.Context) error }            = (*workerprocess.ControlWorkerSupervisor)(nil)
)

type processBoundaryKey struct {
	file   string
	source string
	symbol string
}

type processBoundaryScan struct {
	calls      map[processBoundaryKey]int
	references map[processBoundaryKey]int
	exports    map[string]int
	violations []string
}

var guardedWorkerProcessAPI = map[string]struct{}{
	"NewControlWorkerSupervisor": {},
	"IsControlWorkerChild":       {},
	"AcceptControlWorkerChild":   {},
	"ReportControlWorkerReady":   {},
	"ExitControlWorkerFatal":     {},
	"CloseControlWorkerChild":    {},
}

var guardedWorkerProcessInternals = map[string]struct{}{
	"defaultSupervisorSettings":  {},
	"newControlWorkerSupervisor": {},
	"runControlWorkerSupervisor": {},
	"acceptControlWorkerChild":   {},
	"newChildStatus":             {},
	"buildControlWorkerCommand":  {},
	"startControlWorker":         {},
	"writeStatusByte":            {},
}

var expectedProcessBoundaryCalls = map[processBoundaryKey]int{
	{file: "cmd/worker/main.go", source: workerProcessImport, symbol: "NewControlWorkerSupervisor"}:                  1,
	{file: "cmd/worker/main.go", source: workerProcessImport, symbol: "IsControlWorkerChild"}:                        1,
	{file: "cmd/worker/main.go", source: workerProcessImport, symbol: "AcceptControlWorkerChild"}:                    1,
	{file: "cmd/worker/main.go", source: workerProcessImport, symbol: "CloseControlWorkerChild"}:                     1,
	{file: "internal/workerprocess/supervisor.go", source: "workerprocess", symbol: "defaultSupervisorSettings"}:     1,
	{file: "internal/workerprocess/supervisor.go", source: "workerprocess", symbol: "newControlWorkerSupervisor"}:    1,
	{file: "internal/workerprocess/supervisor.go", source: "workerprocess", symbol: "runControlWorkerSupervisor"}:    1,
	{file: "internal/workerprocess/protocol.go", source: "workerprocess", symbol: "acceptControlWorkerChild"}:        1,
	{file: "internal/workerprocess/protocol.go", source: workerProcessImport, symbol: "IsControlWorkerChild"}:        1,
	{file: "internal/workerprocess/platform_linux.go", source: "workerprocess", symbol: "newChildStatus"}:            1,
	{file: "internal/workerprocess/platform_linux.go", source: "workerprocess", symbol: "buildControlWorkerCommand"}: 1,
	{file: "internal/workerprocess/platform_linux.go", source: "workerprocess", symbol: "startControlWorker"}:        1,
	{file: "internal/workerprocess/protocol.go", source: "workerprocess", symbol: "writeStatusByte"}:                 2,
	{file: "internal/workerprocess/platform_linux.go", source: "os/exec", symbol: "Command"}:                         1,
}

var expectedWorkerProcessExports = map[string]int{
	"type:ControlWorkerSupervisor":       1,
	"type:ChildStatus":                   1,
	"func:NewControlWorkerSupervisor":    1,
	"func:IsControlWorkerChild":          1,
	"func:AcceptControlWorkerChild":      1,
	"func:ReportControlWorkerReady":      1,
	"func:ExitControlWorkerFatal":        1,
	"func:CloseControlWorkerChild":       1,
	"method:ControlWorkerSupervisor.Run": 1,
	"method:boundedDiscard.Write":        1,
}

var expectedRawExecReferences = map[processBoundaryKey]int{
	{file: "internal/workerprocess/platform_linux.go", source: "os/exec", symbol: "Cmd"}: 2,
}

var rawExecImportAllowlist = map[string]struct{}{
	"internal/workerprocess/platform_linux.go":        {},
	"internal/isolatedexec/platform_linux.go":         {},
	"internal/isolatedexec/platform_other.go":         {},
	"internal/isolatedexec/process.go":                {},
	"internal/isolatedexec/testdata/executor/main.go": {},
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

func TestProcessBoundaryScannerRejectsAliasesAndAlternateExec(t *testing.T) {
	root := t.TempDir()
	writeProcessBoundaryFixture(t, root, "cmd/worker/main.go", `package main

import (
	worker "github.com/seaworld008/aiops-system/internal/workerprocess"
	"os/exec"
)

func bypass(status *worker.ChildStatus) {
	ctor := worker.NewControlWorkerSupervisor
	ctor()
	_ = worker.AcceptControlWorkerChild
	worker.ReportControlWorkerReady(status)
	worker.ExitControlWorkerFatal(status)
	exec.CommandContext(nil, "sh")
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
		"exports unreviewed func:NewSupervisorWithEnv",
	} {
		if !strings.Contains(violations, expected) {
			t.Errorf("scanner violations do not contain %q; got:\n%s", expected, violations)
		}
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
		calls:      make(map[processBoundaryKey]int),
		references: make(map[processBoundaryKey]int),
		exports:    make(map[string]int),
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
			strings.HasPrefix(relative, "internal/workerprocess/")
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
			if importPath == workerProcessImport && relative != "cmd/worker/main.go" {
				scan.violations = append(scan.violations, fmt.Sprintf(
					"production file %s imports workerprocess outside the sole cmd/worker assembly", relative))
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
