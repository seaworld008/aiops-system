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
	ast.Inspect(factory.Body, func(node ast.Node) bool {
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
	buildPosition := token.NoPos
	factoryPosition := token.NoPos
	unexpectedReadyCalls := 0
	ast.Inspect(assembly.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch calledFunctionName(call.Fun) {
		case "BuildControlWorkerSnapshot":
			if buildPosition != token.NoPos {
				t.Error("snapshot gate is called more than once")
			}
			buildPosition = call.Pos()
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
	if buildPosition == token.NoPos || factoryPosition == token.NoPos || buildPosition >= factoryPosition {
		t.Fatalf("production order is snapshot=%s factory=%s", files.Position(buildPosition), files.Position(factoryPosition))
	}
	if unexpectedReadyCalls != 0 {
		t.Fatalf("pre-runtime assembly contains %d status READY calls", unexpectedReadyCalls)
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
	if allReadyCalls != 4 {
		t.Fatalf("control child production Ready callsites = %d, want exact reviewed set of 4", allReadyCalls)
	}
	if readyHelperCalls != 1 {
		t.Fatalf("control child READY helper callsites = %d, want exact reviewed lifecycle call", readyHelperCalls)
	}
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
