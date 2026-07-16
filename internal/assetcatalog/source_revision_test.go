package assetcatalog

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type sourceRevisionRepositoryABI struct{}

func (sourceRevisionRepositoryABI) CreateSource(context.Context, CreateSourceCommand) (SourceRevisionMutation, error) {
	return SourceRevisionMutation{}, nil
}

func (sourceRevisionRepositoryABI) CreateRevision(context.Context, CreateSourceRevisionCommand) (SourceRevisionMutation, error) {
	return SourceRevisionMutation{}, nil
}

func (sourceRevisionRepositoryABI) RequestValidation(context.Context, ValidateSourceRevisionCommand) (SourceRunMutation, error) {
	return SourceRunMutation{}, nil
}

func (sourceRevisionRepositoryABI) Publish(context.Context, PublishSourceRevisionCommand) (SourceRevisionMutation, error) {
	return SourceRevisionMutation{}, nil
}

func (sourceRevisionRepositoryABI) Disable(context.Context, DisableSourceCommand) (SourceMutation, error) {
	return SourceMutation{}, nil
}

func (sourceRevisionRepositoryABI) RequestSync(context.Context, RequestSyncCommand) (SourceRunMutation, error) {
	return SourceRunMutation{}, nil
}

var _ SourceRevisionRepository = sourceRevisionRepositoryABI{}

func TestSourceRevisionCommandsCloneOwnedAuthorityState(t *testing.T) {
	createSource := CreateSourceCommand{
		Name:                    "manual source",
		SourceProfileID:         SourceProfileIDManualV1,
		AuthorityEnvironmentIDs: []string{"30000000-0000-4000-8000-000000000002", "30000000-0000-4000-8000-000000000001"},
	}
	clonedSource := createSource.Clone()
	createSource.AuthorityEnvironmentIDs[0] = "30000000-0000-4000-8000-000000000099"
	if clonedSource.AuthorityEnvironmentIDs[0] == createSource.AuthorityEnvironmentIDs[0] {
		t.Fatalf("CreateSourceCommand.Clone() aliased caller-owned state: %#v", clonedSource)
	}

	createRevision := CreateSourceRevisionCommand{
		SourceID:                "60000000-0000-4000-8000-000000000001",
		SourceProfileID:         SourceProfileIDManualV1,
		AuthorityEnvironmentIDs: []string{"30000000-0000-4000-8000-000000000002", "30000000-0000-4000-8000-000000000001"},
		ChangeReasonCode:        "SOURCE_CONFIGURATION_CHANGED",
		ExpectedSourceVersion:   7,
	}

	clonedRevision := createRevision.Clone()
	createRevision.AuthorityEnvironmentIDs[0] = "30000000-0000-4000-8000-000000000099"

	if clonedRevision.AuthorityEnvironmentIDs[0] == createRevision.AuthorityEnvironmentIDs[0] {
		t.Fatalf("CreateSourceRevisionCommand.Clone() aliased caller-owned state: %#v", clonedRevision)
	}
}

func TestSourceRevisionMutationsCloneNestedValues(t *testing.T) {
	result := SourceRunMutation{
		Revision: SourceRevision{
			CanonicalProfileManifest: []byte(`{"safe":true}`),
			AuthorityEnvironmentIDs:  []string{"30000000-0000-4000-8000-000000000001"},
		},
	}
	cloned := result.Clone()
	result.Revision.CanonicalProfileManifest[0] = '!'
	result.Revision.AuthorityEnvironmentIDs[0] = "30000000-0000-4000-8000-000000000099"

	if cloned.Revision.CanonicalProfileManifest[0] == result.Revision.CanonicalProfileManifest[0] ||
		cloned.Revision.AuthorityEnvironmentIDs[0] == result.Revision.AuthorityEnvironmentIDs[0] {
		t.Fatalf("SourceRunMutation.Clone() aliased nested revision state: %#v", cloned)
	}
}

func TestSourceRevisionCommandsExposeExactCASCoordinates(t *testing.T) {
	assertFields := func(value any, fields ...string) {
		t.Helper()
		typ := reflect.TypeOf(value)
		for _, field := range fields {
			if _, ok := typ.FieldByName(field); !ok {
				t.Errorf("%s lacks exact CAS field %s", typ.Name(), field)
			}
		}
	}

	assertFields(CreateSourceCommand{}, "Context", "Name", "SourceProfileID", "AuthorityEnvironmentIDs")
	assertFields(CreateSourceRevisionCommand{}, "Context", "SourceID", "SourceProfileID", "ExpectedSourceVersion")
	assertFields(ValidateSourceRevisionCommand{},
		"Context", "SourceID", "Revision", "ExpectedSourceVersion", "ExpectedRevisionVersion", "ExpectedRevisionDigest")
	assertFields(PublishSourceRevisionCommand{},
		"Context", "SourceID", "Revision", "ExpectedSourceVersion", "ExpectedRevisionVersion",
		"ExpectedRevisionDigest", "ExpectedValidationRunID", "ExpectedValidationDigest")
	assertFields(DisableSourceCommand{}, "Context", "SourceID", "ExpectedSourceVersion")
	assertFields(RequestSyncCommand{},
		"Context", "SourceID", "ExpectedSourceVersion", "ExpectedRevision", "ExpectedRevisionDigest",
		"ExpectedCheckpointVersion", "ExpectedCheckpointSHA256")
}

func TestSourceRevisionCommandsHaveNoArbitraryOrSecretBearingSurface(t *testing.T) {
	for _, value := range []any{
		CreateSourceCommand{},
		CreateSourceRevisionCommand{},
		ValidateSourceRevisionCommand{},
		PublishSourceRevisionCommand{},
		DisableSourceCommand{},
		RequestSyncCommand{},
	} {
		typ := reflect.TypeOf(value)
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			name := strings.ToLower(field.Name)
			for _, forbidden := range []string{"endpoint", "header", "body", "secret", "password", "token", "privatekey", "rawcredential"} {
				if strings.Contains(name, forbidden) {
					t.Errorf("%s.%s exposes forbidden command surface", typ.Name(), field.Name)
				}
			}
			if field.Type.Kind() == reflect.Map || field.Type == reflect.TypeOf([]byte(nil)) {
				t.Errorf("%s.%s exposes unbounded/map or raw byte command surface", typ.Name(), field.Name)
			}
		}
	}
}

func TestSourceCreateCommandsCannotCarryResolvedProfileFacts(t *testing.T) {
	for _, command := range []any{CreateSourceCommand{}, CreateSourceRevisionCommand{}} {
		typ := reflect.TypeOf(command)
		for _, forbidden := range []string{
			"ProfileCode", "Profile", "BuiltinSourceProfile", "CanonicalProfileManifest",
			"CanonicalProviderSchema", "SourceKind", "ProviderKind", "IntegrationID",
			"CredentialReferenceID", "TrustReferenceID", "NetworkPolicyReferenceID",
			"SyncMode", "ScheduleExpression", "RateLimitRequests", "FreshnessKind",
			"EnvironmentMapping", "TypedExtensionCode", "PreparedExtensionDigest",
		} {
			if field, ok := typ.FieldByName(forbidden); ok {
				t.Errorf("%s exposes caller-constructible resolved profile field %s (%s)", typ.Name(), field.Name, field.Type)
			}
		}
	}
}

func TestSourceProfileIDIsNotAPersistedSourceOrRevisionFact(t *testing.T) {
	for _, value := range []any{Source{}, SourceRevision{}, SourceRevisionMutation{}} {
		typ := reflect.TypeOf(value)
		if _, found := typ.FieldByName("SourceProfileID"); found {
			t.Errorf("%s persists public SourceProfileID selector", typ.Name())
		}
	}
}

func TestSourceRevisionNotValidatedErrorIsStableAndSafe(t *testing.T) {
	if !errors.Is(ErrSourceRevisionNotValidated, ErrSourceRevisionNotValidated) {
		t.Fatal("ErrSourceRevisionNotValidated is not a stable sentinel")
	}
	if got := ErrSourceRevisionNotValidated.Error(); got != "source revision not validated" {
		t.Fatalf("ErrSourceRevisionNotValidated = %q", got)
	}
}
