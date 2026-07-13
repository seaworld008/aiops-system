package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

func TestControlWorkerSnapshotGateStillCannotCreateRuntimeOrReportReady(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate control child assembly boundary test")
	}
	path := filepath.Join(filepath.Dir(currentFile), "control_child.go")
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	factory := findControlChildFunction(parsed, "newControlChildRuntime")
	assembly := findControlChildFunction(parsed, "runControlWorkerChildRuntime")
	if factory == nil || assembly == nil {
		t.Fatal("control child assembly functions are missing")
	}
	returns := 0
	factoryCalls := make(map[string]int)
	ast.Inspect(factory.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			factoryCalls[calledFunctionName(call.Fun)]++
		}
		statement, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		returns++
		if len(statement.Results) != 2 || !identifierNamed(statement.Results[0], "nil") ||
			!identifierNamed(statement.Results[1], "errControlWorkerAssemblyUnavailable") {
			t.Errorf("runtime factory has a non-fail-closed return at %s", files.Position(statement.Pos()))
		}
		return true
	})
	if returns == 0 {
		t.Fatal("runtime factory has no fixed unavailable return")
	}
	if len(factoryCalls) != 1 || factoryCalls["Ready"] != 1 {
		t.Fatalf("runtime factory calls = %#v, want only Snapshot.Ready", factoryCalls)
	}
	buildPosition := token.NoPos
	secretReadyPosition := token.NoPos
	bindPosition := token.NoPos
	factoryPosition := token.NoPos
	unexpectedReadyCalls := 0
	assemblyCalls := make(map[string]int)
	ast.Inspect(assembly.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calledFunctionName(call.Fun)
		assemblyCalls[name]++
		switch name {
		case "BuildControlWorkerSnapshot":
			if buildPosition != token.NoPos {
				t.Error("snapshot gate is called more than once")
			}
			buildPosition = call.Pos()
		case "ReportControlWorkerSecretReady":
			if secretReadyPosition != token.NoPos {
				t.Error("secret-ready barrier is called more than once")
			}
			secretReadyPosition = call.Pos()
		case "BindControlWorkerSecrets":
			if bindPosition != token.NoPos {
				t.Error("secret binding is called more than once")
			}
			bindPosition = call.Pos()
		case "newControlChildRuntime":
			if factoryPosition != token.NoPos {
				t.Error("runtime factory is called more than once")
			}
			factoryPosition = call.Pos()
		case "ReportControlWorkerReady", "reportControlChildReady":
			unexpectedReadyCalls++
		case "Ready":
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				unexpectedReadyCalls++
				break
			}
			receiver, receiverOK := selector.X.(*ast.Ident)
			if !receiverOK || receiver.Name != "snapshot" {
				unexpectedReadyCalls++
			}
		}
		return true
	})
	if buildPosition == token.NoPos || secretReadyPosition == token.NoPos || bindPosition == token.NoPos ||
		factoryPosition == token.NoPos || buildPosition >= secretReadyPosition ||
		secretReadyPosition >= bindPosition || bindPosition >= factoryPosition {
		t.Fatalf(
			"production order is snapshot=%s secret-ready=%s bind=%s factory=%s",
			files.Position(buildPosition), files.Position(secretReadyPosition),
			files.Position(bindPosition), files.Position(factoryPosition),
		)
	}
	if unexpectedReadyCalls != 0 {
		t.Fatalf("pre-runtime assembly contains %d status READY calls", unexpectedReadyCalls)
	}
	wantAssemblyCalls := map[string]int{
		"Err":                            2,
		"CloseControlWorkerChild":        2,
		"BuildControlWorkerSnapshot":     1,
		"Ready":                          1,
		"ReportControlWorkerSecretReady": 1,
		"BindControlWorkerSecrets":       1,
		"newControlChildRuntime":         1,
		"nilControlChildDependency":      1,
		"newControlChild":                1,
		"Run":                            1,
	}
	if !sameControlChildStringCounts(assemblyCalls, wantAssemblyCalls) {
		t.Fatalf("pre-runtime assembly calls = %#v, want exact reviewed set %#v", assemblyCalls, wantAssemblyCalls)
	}
	allReadyCalls := 0
	readyHelperCalls := 0
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok {
			switch calledFunctionName(call.Fun) {
			case "Ready":
				allReadyCalls++
			case "reportControlChildReady":
				readyHelperCalls++
			}
		}
		return true
	})
	if allReadyCalls != 3 {
		t.Fatalf("control child production Ready callsites = %d, want exact reviewed set of 3", allReadyCalls)
	}
	if readyHelperCalls != 1 {
		t.Fatalf("control child READY helper callsites = %d, want exact reviewed lifecycle call", readyHelperCalls)
	}
}

func sameControlChildStringCounts(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func findControlChildFunction(file *ast.File, name string) *ast.FuncDecl {
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv == nil && function.Name.Name == name {
			return function
		}
	}
	return nil
}

func identifierNamed(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}

func calledFunctionName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	default:
		return ""
	}
}
