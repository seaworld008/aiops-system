package readassembly_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type canonicalCall struct {
	file       string
	importPath string
	symbol     string
}

type canonicalPackageSymbol struct {
	directory string
	symbol    string
}

var guardedCanonicalCalls = map[canonicalCall]int{
	{file: "internal/workerbootstrap/inherit.go", importPath: "github.com/seaworld008/aiops-system/internal/readassembly", symbol: "LoadCanonicalManifests"}: 1,
	{file: "internal/readassembly/snapshot.go", importPath: "github.com/seaworld008/aiops-system/internal/readconnector", symbol: "CompileManifest"}:         1,
	{file: "internal/readassembly/snapshot.go", importPath: "github.com/seaworld008/aiops-system/internal/investigationplan", symbol: "CompileManifest"}:     1,
	{file: "internal/readassembly/snapshot.go", importPath: "github.com/seaworld008/aiops-system/internal/readtarget", symbol: "CompileCapturedManifest"}:    1,
	{file: "internal/readassembly/snapshot.go", importPath: "github.com/seaworld008/aiops-system/internal/readexecutor", symbol: "CompileEgressManifest"}:    1,
}

var guardedCanonicalPackageSymbols = map[canonicalPackageSymbol]int{
	{directory: "internal/readassembly", symbol: "LoadCanonicalManifests"}: 1,
	{directory: "internal/readconnector", symbol: "CompileManifest"}:       1,
	{directory: "internal/investigationplan", symbol: "CompileManifest"}:   1,
	{directory: "internal/readtarget", symbol: "CompileCapturedManifest"}:  1,
	{directory: "internal/readexecutor", symbol: "CompileEgressManifest"}:  1,
}

func TestCanonicalManifestFriendAPIsHaveOneDirectProductionChain(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate canonical boundary test")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../.."))
	calls := make(map[canonicalCall]int)
	references := make(map[canonicalCall]int)
	buildSnapshotCalls := make(map[string]int)
	buildSnapshotReferences := make(map[string]int)
	var violations []string
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
		aliases := make(map[string]string)
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if !guardedCanonicalImport(importPath) {
				continue
			}
			alias := filepath.Base(importPath)
			if imported.Name != nil {
				violations = append(violations, relative+" aliases guarded canonical import "+importPath)
				continue
			}
			aliases[alias] = importPath
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.SelectorExpr:
				identifier, ok := typed.X.(*ast.Ident)
				if ok {
					if importPath, found := aliases[identifier.Name]; found && guardedCanonicalSymbol(importPath, typed.Sel.Name) {
						references[canonicalCall{file: relative, importPath: importPath, symbol: typed.Sel.Name}]++
					}
				}
				if typed.Sel.Name == "BuildSnapshot" {
					buildSnapshotReferences[relative]++
				}
			case *ast.CallExpr:
				selector, ok := typed.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				identifier, ok := selector.X.(*ast.Ident)
				if ok {
					if importPath, found := aliases[identifier.Name]; found && guardedCanonicalSymbol(importPath, selector.Sel.Name) {
						calls[canonicalCall{file: relative, importPath: importPath, symbol: selector.Sel.Name}]++
					}
				}
				if selector.Sel.Name == "BuildSnapshot" {
					buildSnapshotCalls[relative]++
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan canonical boundary: %v", err)
	}
	if !sameCanonicalCounts(calls, guardedCanonicalCalls) {
		t.Errorf("canonical calls = %#v, want %#v", calls, guardedCanonicalCalls)
	}
	if !sameCanonicalCounts(references, guardedCanonicalCalls) {
		t.Errorf("canonical references = %#v, want direct calls only %#v", references, guardedCanonicalCalls)
	}
	packageReferences, err := scanCanonicalPackageReferences(repositoryRoot)
	if err != nil {
		t.Fatalf("scan same-package canonical references: %v", err)
	}
	if !sameCanonicalPackageCounts(packageReferences, guardedCanonicalPackageSymbols) {
		t.Errorf("same-package canonical references = %#v, want declarations only %#v", packageReferences, guardedCanonicalPackageSymbols)
	}
	wantBuild := map[string]int{"internal/workerprocess/protocol.go": 1}
	if !sameStringCounts(buildSnapshotCalls, wantBuild) || !sameStringCounts(buildSnapshotReferences, wantBuild) {
		t.Errorf("BuildSnapshot calls/references = %#v/%#v, want %#v", buildSnapshotCalls, buildSnapshotReferences, wantBuild)
	}
	for _, violation := range violations {
		t.Error(violation)
	}
}

func TestCanonicalBoundaryScannerRejectsSamePackageCallsAndFunctionValues(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "internal/readassembly")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := []byte(`package readassembly

func LoadCanonicalManifests() {}

func bypass() {
	LoadCanonicalManifests()
	alias := LoadCanonicalManifests
	alias()
}
`)
	if err := os.WriteFile(filepath.Join(directory, "bypass.go"), fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	references, err := scanCanonicalPackageReferences(root)
	if err != nil {
		t.Fatal(err)
	}
	key := canonicalPackageSymbol{directory: "internal/readassembly", symbol: "LoadCanonicalManifests"}
	if references[key] <= guardedCanonicalPackageSymbols[key] {
		t.Fatalf("scanner accepted same-package call/function value: %#v", references)
	}
}

func scanCanonicalPackageReferences(repositoryRoot string) (map[canonicalPackageSymbol]int, error) {
	references := make(map[canonicalPackageSymbol]int)
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
		directory := filepath.Dir(relative)
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			key := canonicalPackageSymbol{directory: directory, symbol: identifier.Name}
			if _, guarded := guardedCanonicalPackageSymbols[key]; guarded {
				references[key]++
			}
			return true
		})
		return nil
	})
	return references, err
}

func guardedCanonicalImport(importPath string) bool {
	for key := range guardedCanonicalCalls {
		if key.importPath == importPath {
			return true
		}
	}
	return false
}

func guardedCanonicalSymbol(importPath, symbol string) bool {
	for key := range guardedCanonicalCalls {
		if key.importPath == importPath && key.symbol == symbol {
			return true
		}
	}
	return false
}

func sameCanonicalCounts(left, right map[canonicalCall]int) bool {
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

func sameStringCounts(left, right map[string]int) bool {
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

func sameCanonicalPackageCounts(left, right map[canonicalPackageSymbol]int) bool {
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
