package assetcatalog

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/authn"
)

func TestMutationContextRejectsZeroAndMalformedState(t *testing.T) {
	t.Parallel()

	if err := (MutationContext{}).Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero MutationContext.Validate() error = %v, want ErrInvalidRequest", err)
	}
	principal := validMutationPrincipal()
	scope := Scope{TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID}
	metadata := validMutationMetadata()
	value, err := NewMutationContext(principal, scope, metadata)
	if err != nil {
		t.Fatalf("NewMutationContext() error = %v", err)
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("MutationContext.Validate() error = %v", err)
	}
	if got, ok := value.EnvironmentScope(); !ok || got != scope {
		t.Fatalf("EnvironmentScope() = (%#v, %v), want %#v", got, ok, scope)
	}
	if got := value.SourceScope(); got != (SourceScope{TenantID: testTenantID, WorkspaceID: testWorkspaceID}) {
		t.Fatalf("SourceScope() = %#v", got)
	}
	if value.ActorID() != "oidc:subject-1" || value.SubjectID() != principal.Subject || !value.AuthenticatedAt().Equal(principal.AuthenticatedAt) ||
		value.TraceID() != metadata.TraceID || value.IdempotencyKey() != metadata.IdempotencyKey || value.RequestHash() != metadata.RequestHash {
		t.Fatalf("MutationContext trusted getters drifted")
	}

	for name, mutate := range map[string]func(*MutationContext){
		"zero scope kind":    func(candidate *MutationContext) { candidate.scopeKind = 0 },
		"unknown scope kind": func(candidate *MutationContext) { candidate.scopeKind = 255 },
		"tenant":             func(candidate *MutationContext) { candidate.sourceScope.TenantID = "" },
		"workspace": func(candidate *MutationContext) {
			candidate.sourceScope.WorkspaceID = strings.ToUpper(testLetteredUUID)
		},
		"environment":       func(candidate *MutationContext) { candidate.environmentID = "not-a-uuid" },
		"actor consistency": func(candidate *MutationContext) { candidate.actorID = "oidc:other-subject" },
		"subject":           func(candidate *MutationContext) { candidate.subjectID = "subject\nunsafe" },
		"authentication":    func(candidate *MutationContext) { candidate.authenticatedAt = time.Time{} },
		"trace":             func(candidate *MutationContext) { candidate.traceID = "trace\nunsafe" },
		"idempotency key":   func(candidate *MutationContext) { candidate.idempotencyKey = "Asset Create" },
		"canonical request": func(candidate *MutationContext) { candidate.requestHash = strings.ToUpper(testDigestA) },
	} {
		candidate := value
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("malformed %s MutationContext.Validate() error = %v, want ErrInvalidRequest", name, err)
		}
	}
}

func TestMutationContextConstructorsBindPrincipalTenantAndExactScopeKind(t *testing.T) {
	t.Parallel()

	principal := validMutationPrincipal()
	metadata := validMutationMetadata()
	environmentScope := Scope{TenantID: testTenantID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironmentID}
	environmentContext, err := NewMutationContext(principal, environmentScope, metadata)
	if err != nil {
		t.Fatalf("NewMutationContext() error = %v", err)
	}
	if _, ok := environmentContext.EnvironmentScope(); !ok {
		t.Fatal("environment MutationContext lost Environment scope")
	}

	sourceScope := SourceScope{TenantID: testTenantID, WorkspaceID: testWorkspaceID}
	sourceContext, err := NewSourceMutationContext(principal, sourceScope, metadata)
	if err != nil {
		t.Fatalf("NewSourceMutationContext() error = %v", err)
	}
	if sourceContext.SourceScope() != sourceScope {
		t.Fatalf("source MutationContext scope = %#v", sourceContext.SourceScope())
	}
	if got, ok := sourceContext.EnvironmentScope(); ok || got != (Scope{}) {
		t.Fatalf("source MutationContext fabricated EnvironmentScope = (%#v, %v)", got, ok)
	}
	forgedSource := sourceContext
	forgedSource.environmentID = testEnvironmentID
	if err := forgedSource.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("source MutationContext with forged Environment error = %v, want ErrInvalidRequest", err)
	}
	forgedEnvironment := environmentContext
	forgedEnvironment.scopeKind = sourceContext.scopeKind
	if err := forgedEnvironment.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("environment MutationContext with source scope kind error = %v, want ErrInvalidRequest", err)
	}

	tests := map[string]func() error{
		"tenant mismatch": func() error {
			changed := environmentScope
			changed.TenantID = "77777777-7777-4777-8777-777777777777"
			_, err := NewMutationContext(principal, changed, metadata)
			return err
		},
		"noncanonical principal tenant": func() error {
			changed := principal
			changed.TenantID = strings.ToUpper(testLetteredUUID)
			_, err := NewMutationContext(changed, environmentScope, metadata)
			return err
		},
		"missing principal subject": func() error {
			changed := principal
			changed.Subject = ""
			_, err := NewMutationContext(changed, environmentScope, metadata)
			return err
		},
		"zero authentication time": func() error {
			changed := principal
			changed.AuthenticatedAt = time.Time{}
			_, err := NewMutationContext(changed, environmentScope, metadata)
			return err
		},
		"non-UTC authentication time": func() error {
			changed := principal
			changed.AuthenticatedAt = changed.AuthenticatedAt.In(time.FixedZone("unsafe", 3600))
			_, err := NewMutationContext(changed, environmentScope, metadata)
			return err
		},
		"sub-microsecond authentication time": func() error {
			changed := principal
			changed.AuthenticatedAt = changed.AuthenticatedAt.Add(time.Nanosecond)
			_, err := NewMutationContext(changed, environmentScope, metadata)
			return err
		},
		"invalid trace": func() error {
			changed := metadata
			changed.TraceID = "trace\nunsafe"
			_, err := NewMutationContext(principal, environmentScope, changed)
			return err
		},
		"invalid idempotency key": func() error {
			changed := metadata
			changed.IdempotencyKey = "Asset Create"
			_, err := NewMutationContext(principal, environmentScope, changed)
			return err
		},
		"invalid request hash": func() error {
			changed := metadata
			changed.RequestHash = strings.ToUpper(testDigestA)
			_, err := NewMutationContext(principal, environmentScope, changed)
			return err
		},
	}
	for name, run := range tests {
		if err := run(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s error = %v, want ErrInvalidRequest", name, err)
		}
	}
	sourceTests := map[string]func() error{
		"tenant mismatch": func() error {
			changed := sourceScope
			changed.TenantID = "77777777-7777-4777-8777-777777777777"
			_, err := NewSourceMutationContext(principal, changed, metadata)
			return err
		},
		"noncanonical scope": func() error {
			changed := sourceScope
			changed.WorkspaceID = strings.ToUpper(testLetteredUUID)
			_, err := NewSourceMutationContext(principal, changed, metadata)
			return err
		},
		"noncanonical principal tenant": func() error {
			changed := principal
			changed.TenantID = strings.ToUpper(testLetteredUUID)
			_, err := NewSourceMutationContext(changed, sourceScope, metadata)
			return err
		},
		"missing principal subject": func() error {
			changed := principal
			changed.Subject = ""
			_, err := NewSourceMutationContext(changed, sourceScope, metadata)
			return err
		},
		"zero authentication time": func() error {
			changed := principal
			changed.AuthenticatedAt = time.Time{}
			_, err := NewSourceMutationContext(changed, sourceScope, metadata)
			return err
		},
		"non-UTC authentication time": func() error {
			changed := principal
			changed.AuthenticatedAt = changed.AuthenticatedAt.In(time.FixedZone("unsafe", 3600))
			_, err := NewSourceMutationContext(changed, sourceScope, metadata)
			return err
		},
		"sub-microsecond authentication time": func() error {
			changed := principal
			changed.AuthenticatedAt = changed.AuthenticatedAt.Add(time.Nanosecond)
			_, err := NewSourceMutationContext(changed, sourceScope, metadata)
			return err
		},
		"invalid trace": func() error {
			changed := metadata
			changed.TraceID = "trace\nunsafe"
			_, err := NewSourceMutationContext(principal, sourceScope, changed)
			return err
		},
		"invalid idempotency key": func() error {
			changed := metadata
			changed.IdempotencyKey = "Asset Create"
			_, err := NewSourceMutationContext(principal, sourceScope, changed)
			return err
		},
		"invalid request hash": func() error {
			changed := metadata
			changed.RequestHash = strings.ToUpper(testDigestA)
			_, err := NewSourceMutationContext(principal, sourceScope, changed)
			return err
		},
	}
	for name, run := range sourceTests {
		if err := run(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("NewSourceMutationContext %s error = %v, want ErrInvalidRequest", name, err)
		}
	}
}

func TestMutationContextCannotBeConstructedFromTransportJSON(t *testing.T) {
	t.Parallel()

	type transportEnvelope struct {
		Context MutationContext `json:"context"`
	}
	var decoded transportEnvelope
	raw := []byte(`{"context":{"scopeKind":1,"tenant_id":"11111111-1111-4111-8111-111111111111","workspace_id":"22222222-2222-4222-8222-222222222222","environment_id":"44444444-4444-4444-8444-444444444444","actor_id":"oidc:attacker","subject_id":"attacker","trace_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","idempotency_key":"asset:create:1","request_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if err := decoded.Context.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("transport-constructed MutationContext.Validate() error = %v", err)
	}

	contextType := reflect.TypeOf(MutationContext{})
	for index := 0; index < contextType.NumField(); index++ {
		field := contextType.Field(index)
		if field.PkgPath == "" {
			t.Errorf("MutationContext field %s is exported", field.Name)
		}
		if field.Tag.Get("json") != "" {
			t.Errorf("MutationContext field %s has transport tag %q", field.Name, field.Tag.Get("json"))
		}
	}
	for _, command := range []reflect.Type{
		reflect.TypeOf(CreateAssetCommand{}), reflect.TypeOf(UpdateGovernanceCommand{}), reflect.TypeOf(TransitionCommand{}),
		reflect.TypeOf(CreateBindingCommand{}), reflect.TypeOf(DeleteBindingCommand{}), reflect.TypeOf(MappingDecision{}),
	} {
		for index := 0; index < command.NumField(); index++ {
			field := command.Field(index)
			if field.Tag.Get("json") != "" {
				t.Errorf("domain command %s.%s has transport tag %q", command.Name(), field.Name, field.Tag.Get("json"))
			}
			for _, forbidden := range []string{"TenantID", "WorkspaceID", "EnvironmentID", "ActorID", "SubjectID", "AuthenticatedAt", "TraceID", "IdempotencyKey", "RequestHash"} {
				if field.Name == forbidden {
					t.Errorf("domain command %s exposes trusted field %s", command.Name(), field.Name)
				}
			}
		}
	}
}

func TestReadConstraintConstructorsDistinguishDenyAllAndRejectForgery(t *testing.T) {
	t.Parallel()

	if err := (AssetReadConstraint{}).Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero AssetReadConstraint.Validate() error = %v", err)
	}
	denyAssets, err := NewAssetReadConstraint(false, nil)
	if err != nil || denyAssets.Validate() != nil || denyAssets.Unrestricted() || len(denyAssets.ServiceIDs()) != 0 {
		t.Fatalf("restricted-empty AssetReadConstraint = (%#v, %v)", denyAssets, err)
	}
	allAssets, err := NewAssetReadConstraint(true, nil)
	if err != nil || allAssets.Validate() != nil || !allAssets.Unrestricted() || len(allAssets.ServiceIDs()) != 0 {
		t.Fatalf("unrestricted AssetReadConstraint = (%#v, %v)", allAssets, err)
	}
	assetInput := []string{testServiceID, testAssetID}
	restrictedAssets, err := NewAssetReadConstraint(false, assetInput)
	if err != nil {
		t.Fatalf("NewAssetReadConstraint() error = %v", err)
	}
	assetInput[0] = testTenantID
	if slices.Contains(restrictedAssets.ServiceIDs(), testTenantID) {
		t.Fatal("NewAssetReadConstraint retained its caller-owned input slice")
	}
	services := restrictedAssets.ServiceIDs()
	if !slices.IsSorted(services) || len(services) != 2 {
		t.Fatalf("AssetReadConstraint.ServiceIDs() = %#v", services)
	}
	services[0] = testTenantID
	if restrictedAssets.ServiceIDs()[0] == testTenantID {
		t.Fatal("AssetReadConstraint.ServiceIDs() leaked internal slice")
	}
	malformedAssets := restrictedAssets
	malformedAssets.serviceIDs = []string{testServiceID, testServiceID}
	if err := malformedAssets.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("forged duplicate AssetReadConstraint.Validate() error = %v", err)
	}
	malformedAssets = allAssets
	malformedAssets.serviceIDs = []string{testServiceID}
	if err := malformedAssets.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("forged unrestricted AssetReadConstraint.Validate() error = %v", err)
	}
	for name, test := range map[string]struct {
		unrestricted bool
		serviceIDs   []string
	}{
		"unrestricted with services": {true, []string{testServiceID}},
		"duplicates":                 {false, []string{testServiceID, testServiceID}},
		"noncanonical":               {false, []string{strings.ToUpper(testLetteredUUID)}},
	} {
		if _, err := NewAssetReadConstraint(test.unrestricted, test.serviceIDs); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("NewAssetReadConstraint(%s) error = %v, want ErrInvalidRequest", name, err)
		}
	}

	if err := (SourceReadConstraint{}).Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero SourceReadConstraint.Validate() error = %v", err)
	}
	for name, environmentIDs := range map[string][]string{
		"constructed empty deny all": nil,
		"one":                        {testEnvironmentID},
		"one hundred":                testUUIDs(100),
	} {
		constraint, err := NewSourceReadConstraint(environmentIDs)
		if err != nil || constraint.Validate() != nil || !slices.IsSorted(constraint.EnvironmentIDs()) || len(constraint.EnvironmentIDs()) != len(environmentIDs) {
			t.Errorf("NewSourceReadConstraint(%s) = (%#v, %v)", name, constraint, err)
		}
	}
	for name, environmentIDs := range map[string][]string{
		"one hundred one": testUUIDs(101),
		"duplicates":      {testEnvironmentID, testEnvironmentID},
		"noncanonical":    {strings.ToUpper(testLetteredUUID)},
	} {
		if _, err := NewSourceReadConstraint(environmentIDs); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("NewSourceReadConstraint(%s) error = %v, want ErrInvalidRequest", name, err)
		}
	}
	sourceInput := []string{testAssetID, testEnvironmentID}
	sourceConstraint, err := NewSourceReadConstraint(sourceInput)
	if err != nil {
		t.Fatal(err)
	}
	sourceInput[0] = testTenantID
	if slices.Contains(sourceConstraint.EnvironmentIDs(), testTenantID) {
		t.Fatal("NewSourceReadConstraint retained its caller-owned input slice")
	}
	environments := sourceConstraint.EnvironmentIDs()
	environments[0] = testTenantID
	if sourceConstraint.EnvironmentIDs()[0] == testTenantID {
		t.Fatal("SourceReadConstraint.EnvironmentIDs() leaked internal slice")
	}
	malformedSources := sourceConstraint
	malformedSources.environmentIDs = []string{testEnvironmentID, testEnvironmentID}
	if err := malformedSources.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("forged SourceReadConstraint.Validate() error = %v", err)
	}
}

func TestTrustedDomainConstructorCallsAreRestrictedToManagement(t *testing.T) {
	t.Parallel()

	root := mutationArchitectureRepositoryRoot(t)
	constructors := map[string]struct{}{
		"NewMutationContext": {}, "NewSourceMutationContext": {},
		"NewAssetReadConstraint": {}, "NewSourceReadConstraint": {},
	}
	constructorBuilds := map[string]string{
		"NewMutationContext":       "MutationContext",
		"NewSourceMutationContext": "MutationContext",
		"NewAssetReadConstraint":   "AssetReadConstraint",
		"NewSourceReadConstraint":  "SourceReadConstraint",
	}
	opaqueTypes := map[string]struct{}{
		"MutationContext": {}, "AssetReadConstraint": {}, "SourceReadConstraint": {},
	}
	const (
		allowedCaller = "internal/assetcatalog/management.go"
		owningFile    = "internal/assetcatalog/repository.go"
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
		declarations := make(map[token.Pos]struct{})
		allowedOpaqueConstruction := make(map[token.Pos]struct{})
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if _, guarded := constructors[function.Name.Name]; guarded {
				declarations[function.Name.Pos()] = struct{}{}
				if relative != owningFile {
					position := fileSet.Position(function.Name.Pos())
					t.Errorf("guarded constructor %s declared outside %s at %s:%d", function.Name.Name, owningFile, relative, position.Line)
				}
			}
			ownedType, ownsConstruction := constructorBuilds[function.Name.Name]
			if !ownsConstruction || relative != owningFile || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch value := node.(type) {
				case *ast.CompositeLit:
					if astTypeName(value.Type) == ownedType {
						allowedOpaqueConstruction[value.Pos()] = struct{}{}
					}
				case *ast.ValueSpec:
					if astTypeName(value.Type) == ownedType {
						allowedOpaqueConstruction[value.Pos()] = struct{}{}
					}
				case *ast.CallExpr:
					if calledFunctionName(value.Fun) == ownedType || isNewOfType(value, ownedType) {
						allowedOpaqueConstruction[value.Pos()] = struct{}{}
					}
				}
				return true
			})
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.Ident:
				if _, guarded := constructors[value.Name]; !guarded {
					return true
				}
				if _, declaration := declarations[value.Pos()]; declaration {
					return true
				}
				if relative != allowedCaller {
					position := fileSet.Position(value.Pos())
					t.Errorf("guarded constructor %s referenced from production %s:%d", value.Name, relative, position.Line)
				}
			case *ast.CompositeLit:
				if _, guarded := opaqueTypes[astTypeName(value.Type)]; guarded {
					if _, allowed := allowedOpaqueConstruction[value.Pos()]; !allowed {
						position := fileSet.Position(value.Pos())
						t.Errorf("opaque trusted type %s constructed outside its constructor at %s:%d", astTypeName(value.Type), relative, position.Line)
					}
				}
			case *ast.ValueSpec:
				if _, guarded := opaqueTypes[astTypeName(value.Type)]; guarded {
					if _, allowed := allowedOpaqueConstruction[value.Pos()]; !allowed {
						position := fileSet.Position(value.Pos())
						t.Errorf("opaque trusted type %s declared directly at %s:%d", astTypeName(value.Type), relative, position.Line)
					}
				}
			case *ast.CallExpr:
				name := calledFunctionName(value.Fun)
				_, conversion := opaqueTypes[name]
				if !conversion {
					for typeName := range opaqueTypes {
						if isNewOfType(value, typeName) {
							name, conversion = typeName, true
							break
						}
					}
				}
				if conversion {
					if _, allowed := allowedOpaqueConstruction[value.Pos()]; !allowed {
						position := fileSet.Position(value.Pos())
						t.Errorf("opaque trusted type %s constructed by conversion/new at %s:%d", name, relative, position.Line)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan production constructor call sites: %v", err)
	}
}

func TestAssetCatalogDomainDoesNotOwnSourceLifecycleOrTransactionCallbacks(t *testing.T) {
	t.Parallel()

	root := mutationArchitectureRepositoryRoot(t)
	assetRoot := filepath.Join(root, "internal/assetcatalog")
	task2OwnedFiles := map[string]bool{
		"internal/assetcatalog/types.go":       true,
		"internal/assetcatalog/validation.go":  true,
		"internal/assetcatalog/lifecycle.go":   true,
		"internal/assetcatalog/repository.go":  true,
		"internal/assetcatalog/lease_fence.go": true,
	}
	forbiddenTypes := map[string]struct{}{
		"MappingStatus": {}, "SourceRevisionRepository": {}, "SourceMutationRepository": {},
		"SourceRevisionTx": {}, "SourceTransaction": {}, "SourceRepository": {},
	}
	forbiddenFunctions := map[string]struct{}{
		"CreateSource": {}, "CreateSourceRevision": {}, "PublishSourceRevision": {},
		"ValidateSourceRevision": {}, "EnqueueSourceRun": {}, "SyncSource": {},
	}
	fileSet := token.NewFileSet()
	err := filepath.WalkDir(assetRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != assetRoot {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !task2OwnedFiles[relative] {
			return nil
		}
		for _, imported := range parsed.Imports {
			pathValue := strings.Trim(imported.Path.Value, `"`)
			if pathValue == "database/sql" || strings.HasPrefix(pathValue, "github.com/jackc/pgx") {
				position := fileSet.Position(imported.Pos())
				t.Errorf("root assetcatalog domain imports SQL transaction package %q at %s:%d", pathValue, relative, position.Line)
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.TypeSpec:
				if _, forbidden := forbiddenTypes[value.Name.Name]; forbidden {
					position := fileSet.Position(value.Pos())
					t.Errorf("Task 2 preempted forbidden type %s at %s:%d", value.Name.Name, relative, position.Line)
				}
				if interfaceType, ok := value.Type.(*ast.InterfaceType); ok {
					ast.Inspect(interfaceType, func(child ast.Node) bool {
						if _, callback := child.(*ast.FuncType); callback && child != interfaceType {
							function := child.(*ast.FuncType)
							if function.Params != nil {
								for _, parameter := range function.Params.List {
									if _, transactionCallback := parameter.Type.(*ast.FuncType); transactionCallback {
										t.Errorf("assetcatalog interface %s exposes a transaction callback", value.Name.Name)
									}
									if _, variadic := parameter.Type.(*ast.Ellipsis); variadic {
										t.Errorf("assetcatalog interface %s exposes variadic transaction/data arguments", value.Name.Name)
									}
								}
							}
						}
						return true
					})
				}
			case *ast.FuncDecl:
				if _, forbidden := forbiddenFunctions[value.Name.Name]; forbidden {
					position := fileSet.Position(value.Pos())
					t.Errorf("Task 2 preempted Source mutation %s at %s:%d", value.Name.Name, relative, position.Line)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan assetcatalog Task 2 ownership boundary: %v", err)
	}
}

func astTypeName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return value.Sel.Name
	default:
		return ""
	}
}

func isNewOfType(call *ast.CallExpr, typeName string) bool {
	return calledFunctionName(call.Fun) == "new" && len(call.Args) == 1 && astTypeName(call.Args[0]) == typeName
}

func calledFunctionName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return value.Sel.Name
	default:
		return ""
	}
}

func validMutationPrincipal() authn.Principal {
	return authn.Principal{
		Subject: "subject-1", TenantID: testTenantID,
		AuthenticatedAt: time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC),
		ExpiresAt:       time.Date(2026, 7, 15, 2, 2, 3, 0, time.UTC),
		Roles:           []authn.Role{authn.RoleSRE}, WorkspaceIDs: []string{testWorkspaceID},
		EnvironmentIDs: []string{testEnvironmentID}, ServiceIDs: []string{testServiceID},
	}
}

func validMutationMetadata() MutationMetadata {
	return MutationMetadata{TraceID: strings.Repeat("a", 32), IdempotencyKey: "asset:create:1", RequestHash: testDigestA}
}

func testUUIDs(count int) []string {
	values := make([]string, count)
	for index := range values {
		values[index] = testUUID(index + 1)
	}
	return values
}

func mutationArchitectureRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve mutation architecture test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "../.."))
}
