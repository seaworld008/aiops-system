package discoverysource

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
)

func TestPageCommitContractExactABI(t *testing.T) {
	t.Parallel()

	assertExactStructFields(t, reflect.TypeOf(PageCommitCoordinates{}), []struct {
		name   string
		typeOf reflect.Type
	}{
		{"Locator", reflect.TypeOf(assetcatalog.SourceLocator{})},
		{"RunID", reflect.TypeOf("")},
		{"PageSequence", reflect.TypeOf(int64(0))},
	})
	assertExactStructFields(t, reflect.TypeOf(PageCommitResult{}), []struct {
		name   string
		typeOf reflect.Type
	}{
		{"RunID", reflect.TypeOf("")},
		{"PageSequence", reflect.TypeOf(int64(0))},
		{"CheckpointVersion", reflect.TypeOf(int64(0))},
		{"CheckpointSHA256", reflect.TypeOf("")},
		{"PageDigestSHA256", reflect.TypeOf("")},
		{"RelationPageDigestSHA256", reflect.TypeOf("")},
		{"FinalPage", reflect.TypeOf(false)},
		{"CompleteSnapshot", reflect.TypeOf(false)},
		{"Replayed", reflect.TypeOf(false)},
	})
	assertExactStructFields(t, reflect.TypeOf(CrossEnvironmentRelationPolicyCoordinates{}), []struct {
		name   string
		typeOf reflect.Type
	}{
		{"SourceEnvironmentID", reflect.TypeOf("")},
		{"TargetEnvironmentID", reflect.TypeOf("")},
		{"RelationshipType", reflect.TypeOf(assetcatalog.RelationshipType(""))},
		{"ProviderPathCode", reflect.TypeOf("")},
	})

	assertExactInterfaceMethods(t, reflect.TypeOf((*PageFactPolicyResolver)(nil)).Elem(), map[string]reflect.Type{
		"ResolvePageFactPolicy":                 reflect.TypeOf((func(context.Context, assetcatalog.SourceRevision) (assetdiscovery.FactPolicy, error))(nil)),
		"ResolveCrossEnvironmentRelationPolicy": reflect.TypeOf((func(context.Context, assetcatalog.SourceRevision, CrossEnvironmentRelationPolicyCoordinates) (assetcatalog.PolicyReferenceID, error))(nil)),
	})
	assertExactInterfaceMethods(t, reflect.TypeOf((*PageCommitter)(nil)).Elem(), map[string]reflect.Type{
		"ApplyPage": reflect.TypeOf((func(context.Context, assetcatalog.LeaseFence, PageCommitCoordinates, Page) (PageCommitResult, error))(nil)),
	})
}

func TestPageCommitContractStableErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		err     error
		message string
	}{
		{"invalid", ErrPageCommitInvalid, "source page commit invalid"},
		{"conflict", ErrPageCommitConflict, "source page commit conflict"},
		{"unavailable", ErrPageCommitUnavailable, "source page commit unavailable"},
	}
	for _, test := range tests {
		if test.err == nil || test.err.Error() != test.message {
			t.Errorf("%s error = %v, want %q", test.name, test.err, test.message)
		}
	}
	for left := range tests {
		for right := left + 1; right < len(tests); right++ {
			if errors.Is(tests[left].err, tests[right].err) || errors.Is(tests[right].err, tests[left].err) {
				t.Errorf("stable errors %s and %s alias", tests[left].name, tests[right].name)
			}
		}
	}
}

func assertExactStructFields(t *testing.T, actual reflect.Type, expected []struct {
	name   string
	typeOf reflect.Type
}) {
	t.Helper()
	if actual.Kind() != reflect.Struct || actual.NumField() != len(expected) {
		t.Fatalf("%s has %d fields, want exact %d-field struct", actual, actual.NumField(), len(expected))
	}
	for index, want := range expected {
		field := actual.Field(index)
		if field.Name != want.name || field.Type != want.typeOf || field.Anonymous {
			t.Errorf("%s field %d = %s %s (anonymous=%t), want %s %s", actual, index, field.Name, field.Type, field.Anonymous, want.name, want.typeOf)
		}
	}
}

func assertExactInterfaceMethods(t *testing.T, actual reflect.Type, expected map[string]reflect.Type) {
	t.Helper()
	if actual.Kind() != reflect.Interface || actual.NumMethod() != len(expected) {
		t.Fatalf("%s has %d methods, want exact %d-method interface", actual, actual.NumMethod(), len(expected))
	}
	for name, want := range expected {
		method, ok := actual.MethodByName(name)
		if !ok {
			t.Errorf("%s missing method %s", actual, name)
			continue
		}
		if method.Type != want {
			t.Errorf("%s.%s type = %s, want %s", actual, name, method.Type, want)
		}
	}
}
