package assetcatalog

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLeaseFenceProductionConstructorCallSites(t *testing.T) {
	t.Parallel()

	root := mutationArchitectureRepositoryRoot(t)
	assertLeaseFenceProductionCallSites(t, root)
}

func assertLeaseFenceProductionCallSites(t *testing.T, root string) {
	t.Helper()
	constructorOwner := map[string]string{
		"FromManualRun":  "internal/assetcatalog/postgres/manual_run.go",
		"FromQueueClaim": "internal/discoveryqueue/postgres/repository.go",
	}
	allowedImports := map[string]bool{
		"internal/assetcatalog/lease_fence.go":           true,
		"internal/assetcatalog/postgres/manual_run.go":   true,
		"internal/discoveryqueue/postgres/repository.go": true,
	}
	const (
		internalImport = "github.com/seaworld008/aiops-system/internal/leasefence"
		owningSource   = "internal/leasefence/fence.go"
	)
	fileSet := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".gitnexus", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		parsed, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return err
		}
		leaseFenceAliases := map[string]bool{}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if importPath != internalImport {
				continue
			}
			if !allowedImports[relative] {
				position := fileSet.Position(imported.Pos())
				t.Errorf("production file imports sealed internal leasefence directly: %s:%d", relative, position.Line)
			}
			alias := "leasefence"
			if imported.Name != nil {
				alias = imported.Name.Name
			}
			if alias == "." || alias == "_" {
				position := fileSet.Position(imported.Pos())
				t.Errorf("sealed internal leasefence import must use a named qualifier at %s:%d", relative, position.Line)
				continue
			}
			leaseFenceAliases[alias] = true
		}
		if relative == owningSource {
			return nil
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			packageName, ok := selector.X.(*ast.Ident)
			if !ok || !leaseFenceAliases[packageName.Name] {
				return true
			}
			allowedFile, guarded := constructorOwner[selector.Sel.Name]
			if guarded && relative != allowedFile {
				position := fileSet.Position(selector.Sel.Pos())
				t.Errorf("lease fence constructor %s referenced from %s:%d; allowed only in %s", selector.Sel.Name, relative, position.Line, allowedFile)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan lease fence production call sites: %v", err)
	}
}
