package workerbootstrap_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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
		for _, imported := range parsed.Imports {
			value, unquoteErr := strconv.Unquote(imported.Path.Value)
			if unquoteErr != nil {
				return unquoteErr
			}
			if value == workerBootstrapImport && !insidePackage {
				violations = append(violations, relative+" imports the unassembled worker bootstrap capability")
			}
		}
		if !insidePackage {
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
		"type:PublicSourceCapability": 1, "type:PublicSourceSummary": 1,
		"value:ErrBootstrapRejected": 1, "value:PublicSourceSchemaVersion": 1,
		"func:OpenProductionSource": 2,
		"method:Summary":            1, "method:Close": 1, "method:String": 1, "method:GoString": 1,
		"method:Format": 1, "method:MarshalJSON": 1, "method:UnmarshalJSON": 1,
	}
	if !reflect.DeepEqual(exports, wantExports) {
		t.Errorf("workerbootstrap exports = %#v, want %#v", exports, wantExports)
	}
	if openProductionDeclarations != 2 || rootLiteralCount != 1 {
		t.Errorf("OpenProductionSource declarations/root literals = %d/%d, want 2/1", openProductionDeclarations, rootLiteralCount)
	}
	for _, violation := range violations {
		t.Error(violation)
	}
}
