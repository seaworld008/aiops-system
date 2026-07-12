package readassembly_test

import (
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
)

const investigationWorkflowImport = "github.com/seaworld008/aiops-system/internal/investigationworkflow"

type assemblyCallKey struct {
	file       string
	importPath string
	symbol     string
}

type runtimeV2AssemblyScan struct {
	restrictedCalls map[assemblyCallKey]int
	rawSDKCalls     map[assemblyCallKey]int
	violations      []string
}

var restrictedAssemblyConstructors = map[string]struct{}{
	"DialRuntimeV2StarterClient":     {},
	"DialRuntimeV2ControlClient":     {},
	"DialTemporalClient":             {},
	"NewStarter":                     {},
	"NewWorker":                      {},
	"NewActivities":                  {},
	"NewRuntimeV2Activities":         {},
	"NewBoundRuntimeV2TemporalRoles": {},
	"NewRuntimeV2Starter":            {},
	"NewRuntimeV2ControlWorker":      {},
}

var expectedAssemblyCalls = map[assemblyCallKey]int{
	{file: "internal/readassembly/consumers.go", importPath: investigationWorkflowImport, symbol: "NewActivities"}:                  1,
	{file: "internal/readassembly/consumers.go", importPath: investigationWorkflowImport, symbol: "NewRuntimeV2Activities"}:         1,
	{file: "internal/readassembly/consumers.go", importPath: investigationWorkflowImport, symbol: "NewBoundRuntimeV2TemporalRoles"}: 1,
}

var rawSDKImportAllowlist = map[string]map[string]struct{}{
	"internal/investigationworkflow/runtime_v2_client.go": {
		"go.temporal.io/sdk/client": {},
	},
	"internal/investigationworkflow/runtime_v2_starter.go": {
		"go.temporal.io/sdk/client": {},
	},
	"internal/investigationworkflow/runtime_v2_control_worker.go": {
		"go.temporal.io/sdk/client": {},
		"go.temporal.io/sdk/worker": {},
	},
	"internal/investigationworkflow/temporal_client.go": {
		"go.temporal.io/sdk/client": {},
	},
	"internal/investigationworkflow/starter.go": {
		"go.temporal.io/sdk/client": {},
	},
	"internal/investigationworkflow/worker.go": {
		"go.temporal.io/sdk/worker": {},
	},
}

var expectedRawSDKCalls = map[assemblyCallKey]int{
	{file: "internal/investigationworkflow/runtime_v2_client.go", importPath: "go.temporal.io/sdk/client", symbol: "DialContext"}: 2,
	{file: "internal/investigationworkflow/temporal_client.go", importPath: "go.temporal.io/sdk/client", symbol: "DialContext"}:   1,
	{file: "internal/investigationworkflow/runtime_v2_control_worker.go", importPath: "go.temporal.io/sdk/worker", symbol: "New"}: 1,
	{file: "internal/investigationworkflow/worker.go", importPath: "go.temporal.io/sdk/worker", symbol: "New"}:                    1,
}

// TestRuntimeV2LowLevelAssemblyCallsitesAreClosed turns the package-level
// friend boundary into a repository gate. C2-4c1b deliberately leaves a few
// exported constructors only because Go has no friend packages; production
// code must still assemble them solely through readassembly.Snapshot.
func TestRuntimeV2LowLevelAssemblyCallsitesAreClosed(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate architecture test")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../.."))

	scan, err := scanRuntimeV2Assembly(repositoryRoot)
	if err != nil {
		t.Fatalf("scan production Go files: %v", err)
	}
	for _, violation := range validateRuntimeV2Assembly(scan) {
		t.Error(violation)
	}
}

// TestRuntimeV2AssemblyScannerRejectsBypasses keeps the gate itself under
// test. The fixture covers direct calls plus aliases and function-value
// references, which must never satisfy the exact direct-call allowlist.
func TestRuntimeV2AssemblyScannerRejectsBypasses(t *testing.T) {
	repositoryRoot := t.TempDir()
	writeAssemblyFixture(t, repositoryRoot, "internal/investigationworkflow/runtime_v2_client.go", `package investigationworkflow

import temporalclient "go.temporal.io/sdk/client"

func bypass() {
	ctor := NewBoundRuntimeV2TemporalRoles
	ctor()
	ctor()
	NewRuntimeV2Starter()
	_ = NewRuntimeV2ControlWorker
	temporalclient.DialContext()
	temporalclient.DialContext()
	dial := temporalclient.DialContext
	dial()
	dial()
	_ = temporalclient.NewLazyClient
}
`)
	writeAssemblyFixture(t, repositoryRoot, "internal/readassembly/consumers.go", `package readassembly

import workflow "github.com/seaworld008/aiops-system/internal/investigationworkflow"

func bypass() {
	activities := workflow.NewActivities
	activities()
	activities()
	workflow.NewRuntimeV2Activities()
	workflow.NewBoundRuntimeV2TemporalRoles()
	_ = workflow.NewRuntimeV2ControlWorker
}
`)
	writeAssemblyFixture(t, repositoryRoot, "internal/rogue/worker.go", `package rogue

import temporalworker "go.temporal.io/sdk/worker"

func bypass() {
	newWorker := temporalworker.New
	newWorker()
	newWorker()
}
`)

	scan, err := scanRuntimeV2Assembly(repositoryRoot)
	if err != nil {
		t.Fatalf("scan violation fixture: %v", err)
	}
	violations := strings.Join(validateRuntimeV2Assembly(scan), "\n")
	for _, expected := range []string{
		"references unqualified low-level constructor NewBoundRuntimeV2TemporalRoles as a value",
		"unqualified low-level constructor NewRuntimeV2Starter",
		"references unqualified low-level constructor NewRuntimeV2ControlWorker as a value",
		"references investigationworkflow.NewActivities as a value",
		"guarded constructor NewActivities in internal/readassembly/consumers.go has 0 production callsites, want exactly 1",
		"references investigationworkflow.NewRuntimeV2ControlWorker as a value",
		"references raw Temporal SDK constructor go.temporal.io/sdk/client.DialContext as a value",
		"references raw Temporal SDK constructor go.temporal.io/sdk/client.NewLazyClient as a value",
		"imports raw Temporal SDK capability go.temporal.io/sdk/worker",
		"references raw Temporal SDK constructor go.temporal.io/sdk/worker.New as a value",
	} {
		if !strings.Contains(violations, expected) {
			t.Errorf("scanner violations do not contain %q; got:\n%s", expected, violations)
		}
	}
}

func writeAssemblyFixture(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func scanRuntimeV2Assembly(repositoryRoot string) (runtimeV2AssemblyScan, error) {
	scan := runtimeV2AssemblyScan{
		restrictedCalls: make(map[assemblyCallKey]int),
		rawSDKCalls:     make(map[assemblyCallKey]int),
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
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}

		investigationAliases := make(map[string]struct{})
		rawSDKAliases := make(map[string]string)
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			switch importPath {
			case "go.temporal.io/sdk/client", "go.temporal.io/sdk/worker":
				if _, allowed := rawSDKImportAllowlist[relative][importPath]; !allowed {
					scan.violations = append(scan.violations, fmt.Sprintf(
						"production file %s imports raw Temporal SDK capability %s", relative, importPath))
				}
				alias := filepath.Base(importPath)
				if imported.Name != nil {
					alias = imported.Name.Name
				}
				if alias == "." {
					scan.violations = append(scan.violations, fmt.Sprintf(
						"production file %s dot-imports raw Temporal SDK capability %s", relative, importPath))
					continue
				}
				if alias != "_" {
					rawSDKAliases[alias] = importPath
				}
			case investigationWorkflowImport:
				alias := "investigationworkflow"
				if imported.Name != nil {
					alias = imported.Name.Name
				}
				if alias == "." {
					scan.violations = append(scan.violations, fmt.Sprintf(
						"production file %s dot-imports the low-level Temporal assembly package", relative))
					continue
				}
				if alias != "_" {
					investigationAliases[alias] = struct{}{}
				}
			}
		}

		samePackage := parsed.Name != nil && parsed.Name.Name == "investigationworkflow"
		inspectRuntimeV2Assembly(parsed, func(node, parent ast.Node) {
			switch syntax := node.(type) {
			case *ast.Ident:
				if !samePackage {
					return
				}
				if _, restricted := restrictedAssemblyConstructors[syntax.Name]; !restricted {
					return
				}
				if declaration, ok := parent.(*ast.FuncDecl); ok && declaration.Name == syntax {
					return
				}
				key := assemblyCallKey{file: relative, importPath: investigationWorkflowImport, symbol: syntax.Name}
				if isDirectAssemblyCall(parent, syntax) {
					scan.restrictedCalls[key]++
					scan.violations = append(scan.violations, fmt.Sprintf(
						"production file %s invokes unqualified low-level constructor %s inside investigationworkflow",
						relative, syntax.Name))
					return
				}
				scan.violations = append(scan.violations, fmt.Sprintf(
					"production file %s references unqualified low-level constructor %s as a value inside investigationworkflow",
					relative, syntax.Name))
			case *ast.SelectorExpr:
				qualifier, ok := syntax.X.(*ast.Ident)
				if !ok {
					return
				}
				direct := isDirectAssemblyCall(parent, syntax)
				if _, imported := investigationAliases[qualifier.Name]; imported {
					scanInvestigationWorkflowReference(&scan, relative, syntax.Sel.Name, direct)
					return
				}
				if importPath, imported := rawSDKAliases[qualifier.Name]; imported &&
					isRawSDKConstructor(importPath, syntax.Sel.Name) {
					scanRawSDKReference(&scan, relative, importPath, syntax.Sel.Name, direct)
				}
			}
		})
		return nil
	})
	return scan, err
}

func inspectRuntimeV2Assembly(root ast.Node, visit func(node, parent ast.Node)) {
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

func isDirectAssemblyCall(parent ast.Node, function ast.Expr) bool {
	call, ok := parent.(*ast.CallExpr)
	return ok && call.Fun == function
}

func scanInvestigationWorkflowReference(scan *runtimeV2AssemblyScan, relative, symbol string, direct bool) {
	if _, restricted := restrictedAssemblyConstructors[symbol]; !restricted {
		return
	}
	if !direct {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s references investigationworkflow.%s as a value",
			relative, symbol))
		return
	}
	key := assemblyCallKey{file: relative, importPath: investigationWorkflowImport, symbol: symbol}
	scan.restrictedCalls[key]++
	if _, allowed := expectedAssemblyCalls[key]; !allowed {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s bypasses Snapshot via investigationworkflow.%s", relative, symbol))
	}
}

func scanRawSDKReference(scan *runtimeV2AssemblyScan, relative, importPath, symbol string, direct bool) {
	if !direct {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s references raw Temporal SDK constructor %s.%s as a value",
			relative, importPath, symbol))
		return
	}
	key := assemblyCallKey{file: relative, importPath: importPath, symbol: symbol}
	scan.rawSDKCalls[key]++
	if _, allowed := expectedRawSDKCalls[key]; !allowed {
		scan.violations = append(scan.violations, fmt.Sprintf(
			"production file %s invokes raw Temporal SDK constructor %s.%s",
			relative, importPath, symbol))
	}
}

func isRawSDKConstructor(importPath, symbol string) bool {
	switch importPath {
	case "go.temporal.io/sdk/client":
		return strings.HasPrefix(symbol, "Dial") || strings.HasPrefix(symbol, "New")
	case "go.temporal.io/sdk/worker":
		return strings.HasPrefix(symbol, "New")
	default:
		return false
	}
}

func validateRuntimeV2Assembly(scan runtimeV2AssemblyScan) []string {
	violations := append([]string(nil), scan.violations...)
	for key, expected := range expectedAssemblyCalls {
		if actual := scan.restrictedCalls[key]; actual != expected {
			violations = append(violations, fmt.Sprintf(
				"guarded constructor %s in %s has %d production callsites, want exactly %d",
				key.symbol, key.file, actual, expected))
		}
	}
	for key, expected := range expectedRawSDKCalls {
		if actual := scan.rawSDKCalls[key]; actual != expected {
			violations = append(violations, fmt.Sprintf(
				"raw Temporal SDK constructor %s.%s in %s has %d callsites, want exactly %d",
				key.importPath, key.symbol, key.file, actual, expected))
		}
	}
	sort.Strings(violations)
	return violations
}
