package workerbootstrap_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/workerbootstrap"
)

const workerBootstrapImport = "github.com/seaworld008/aiops-system/internal/workerbootstrap"

var (
	_ func() (*workerbootstrap.PublicSourceCapability, error) = workerbootstrap.OpenProductionSource
	_ interface {
		Summary() workerbootstrap.PublicSourceSummary
		Close() error
	} = (*workerbootstrap.PublicSourceCapability)(nil)
)

func TestPublicSourceAPIExposesNoPathDescriptorOrContents(t *testing.T) {
	capabilityType := reflect.TypeOf(workerbootstrap.PublicSourceCapability{})
	for _, field := range reflect.VisibleFields(capabilityType) {
		if field.IsExported() {
			t.Errorf("PublicSourceCapability exposes field %s", field.Name)
		}
	}
	summaryType := reflect.TypeOf(workerbootstrap.PublicSourceSummary{})
	wantSummary := map[string]reflect.Kind{
		"SchemaVersion": reflect.String, "ManifestSHA256": reflect.String,
		"EnvelopeSHA256": reflect.String, "EnvelopeSize": reflect.Int64,
	}
	if summaryType.NumField() != len(wantSummary) {
		t.Fatalf("PublicSourceSummary has %d fields, want %d", summaryType.NumField(), len(wantSummary))
	}
	for index := range summaryType.NumField() {
		field := summaryType.Field(index)
		kind, ok := wantSummary[field.Name]
		if !ok || !field.IsExported() || field.Type.Kind() != kind {
			t.Errorf("PublicSourceSummary field = %s %s", field.Name, field.Type)
		}
	}
	startChild, ok := reflect.TypeOf((*workerbootstrap.PublicSourceCapability)(nil)).MethodByName("StartChild")
	if !ok || startChild.Type.NumIn() != 3 || startChild.Type.In(1) != reflect.TypeOf((*exec.Cmd)(nil)) ||
		startChild.Type.In(2) != reflect.TypeOf((*os.File)(nil)) || startChild.Type.NumOut() != 1 ||
		startChild.Type.Out(0) != reflect.TypeOf((*error)(nil)).Elem() {
		t.Fatalf("StartChild signature = %#v; want fixed command/status inputs and error only", startChild.Type)
	}
	for index := 0; index < startChild.Type.NumIn(); index++ {
		if startChild.Type.In(index).Kind() == reflect.Func {
			t.Fatal("StartChild exposes a callback that could retain the public-source descriptor")
		}
	}
}

func TestPublicSourceProductionBoundaryRemainsUnassembledAndNonConfigurable(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate architecture test")
	}
	packageDirectory := filepath.Dir(currentFile)
	repositoryRoot := filepath.Clean(filepath.Join(packageDirectory, "../.."))
	exports := make(map[string]int)
	rootLiteralCount := 0
	openProductionDeclarations := 0
	consumerImports := make(map[string]int)
	consumerReferences := make(map[string]int)
	consumerCalls := make(map[string]int)
	handoffReferences := make(map[string]int)
	handoffCalls := make(map[string]int)
	bootstrapStartCalls := make(map[string]int)
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
		parsed, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		relative, relativeErr := filepath.Rel(repositoryRoot, path)
		if relativeErr != nil {
			return relativeErr
		}
		insidePackage := filepath.Dir(relative) == "internal/workerbootstrap"
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.SelectorExpr:
				if typed.Sel.Name == "StartChild" {
					handoffReferences[relative]++
				}
			case *ast.CallExpr:
				selector, ok := typed.Fun.(*ast.SelectorExpr)
				if ok && selector.Sel.Name == "StartChild" {
					handoffCalls[relative]++
				}
				if insidePackage && ok && selector.Sel.Name == "Start" {
					bootstrapStartCalls[relative]++
				}
			}
			return true
		})
		consumerAlias := ""
		for _, imported := range parsed.Imports {
			value, unquoteErr := strconv.Unquote(imported.Path.Value)
			if unquoteErr != nil {
				return unquoteErr
			}
			if value == workerBootstrapImport && !insidePackage {
				consumerImports[relative]++
				if imported.Name != nil {
					violations = append(violations, relative+" aliases the worker bootstrap import")
				} else {
					consumerAlias = "workerbootstrap"
				}
				if relative != "internal/workerprocess/platform_linux.go" {
					violations = append(violations, relative+" imports the worker bootstrap outside the reviewed FD4 handoff")
				}
			}
		}
		if !insidePackage {
			if consumerAlias != "" {
				ast.Inspect(parsed, func(node ast.Node) bool {
					switch typed := node.(type) {
					case *ast.SelectorExpr:
						identifier, ok := typed.X.(*ast.Ident)
						if ok && identifier.Name == consumerAlias {
							consumerReferences[typed.Sel.Name]++
						}
					case *ast.CallExpr:
						selector, ok := typed.Fun.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						identifier, ok := selector.X.(*ast.Ident)
						if ok && identifier.Name == consumerAlias {
							consumerCalls[selector.Sel.Name]++
						}
					}
					return true
				})
			}
			return nil
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.BasicLit:
				if typed.Kind == token.STRING {
					value, unquoteErr := strconv.Unquote(typed.Value)
					if unquoteErr == nil && value == "/run/aiops/control-worker/v1" {
						rootLiteralCount++
					}
				}
			case *ast.CallExpr:
				selector, selectorOK := typed.Fun.(*ast.SelectorExpr)
				if !selectorOK {
					return true
				}
				identifier, identifierOK := selector.X.(*ast.Ident)
				if identifierOK && identifier.Name == "os" &&
					(selector.Sel.Name == "Getenv" || selector.Sel.Name == "LookupEnv" || selector.Sel.Name == "Environ") {
					violations = append(violations, relative+" reads process environment")
				}
			}
			return true
		})
		for _, declaration := range parsed.Decls {
			switch typed := declaration.(type) {
			case *ast.GenDecl:
				for _, specification := range typed.Specs {
					switch value := specification.(type) {
					case *ast.TypeSpec:
						if ast.IsExported(value.Name.Name) {
							exports["type:"+value.Name.Name]++
						}
					case *ast.ValueSpec:
						for _, name := range value.Names {
							if ast.IsExported(name.Name) {
								exports["value:"+name.Name]++
							}
						}
					}
				}
			case *ast.FuncDecl:
				if typed.Recv == nil && typed.Name.Name == "OpenProductionSource" {
					openProductionDeclarations++
					if typed.Type.Params != nil && len(typed.Type.Params.List) != 0 {
						violations = append(violations, relative+" gives OpenProductionSource configurable inputs")
					}
				}
				if ast.IsExported(typed.Name.Name) {
					prefix := "func:"
					if typed.Recv != nil {
						prefix = "method:"
					}
					exports[prefix+typed.Name.Name]++
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan production boundary: %v", err)
	}
	wantExports := map[string]int{
		"type:PublicSourceCapability": 1, "type:PublicSourceSummary": 1, "type:InheritedSource": 1,
		"value:ErrBootstrapRejected": 1, "value:PublicSourceSchemaVersion": 1,
		"func:OpenProductionSource": 2, "func:AcceptInheritedSource": 2,
		"func:WriteProductionSourceToLoaderFD": 2, "func:ReceiveProductionSource": 2,
		"method:Summary": 2, "method:Close": 2, "method:String": 2, "method:GoString": 2,
		"method:Format": 2, "method:MarshalJSON": 2, "method:UnmarshalJSON": 2,
		"method:StartChild": 2,
	}
	if !reflect.DeepEqual(exports, wantExports) {
		t.Errorf("workerbootstrap exports = %#v, want %#v", exports, wantExports)
	}
	if openProductionDeclarations != 2 || rootLiteralCount != 1 {
		t.Errorf("OpenProductionSource declarations/root literals = %d/%d, want 2/1", openProductionDeclarations, rootLiteralCount)
	}
	if !reflect.DeepEqual(consumerImports, map[string]int{"internal/workerprocess/platform_linux.go": 1}) {
		t.Errorf("workerbootstrap production consumers = %#v, want only workerprocess FD4 handoff", consumerImports)
	}
	wantConsumerCalls := map[string]int{
		"WriteProductionSourceToLoaderFD": 1, "ReceiveProductionSource": 1, "AcceptInheritedSource": 1,
	}
	if !reflect.DeepEqual(consumerCalls, wantConsumerCalls) || !reflect.DeepEqual(consumerReferences, wantConsumerCalls) {
		t.Errorf("workerbootstrap consumer calls/references = %#v/%#v, want %#v", consumerCalls, consumerReferences, wantConsumerCalls)
	}
	wantHandoff := map[string]int{"internal/workerprocess/platform_linux.go": 1}
	if !reflect.DeepEqual(handoffReferences, wantHandoff) || !reflect.DeepEqual(handoffCalls, wantHandoff) {
		t.Errorf("public-source StartChild references/calls = %#v/%#v, want the reviewed direct FD4 handoff only", handoffReferences, handoffCalls)
	}
	if !reflect.DeepEqual(bootstrapStartCalls, map[string]int{"internal/workerbootstrap/handoff_linux.go": 1}) {
		t.Errorf("workerbootstrap Start calls = %#v, want only the descriptor-hiding StartChild boundary", bootstrapStartCalls)
	}
	for _, violation := range violations {
		t.Error(violation)
	}
}
