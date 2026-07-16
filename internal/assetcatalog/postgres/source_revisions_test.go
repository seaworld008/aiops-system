package postgres

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

var _ assetcatalog.SourceRevisionRepository = (*Repository)(nil)

func TestMapSourceRevisionErrorPreservesStableSentinel(t *testing.T) {
	if got := mapSourceRevisionError(assetcatalog.ErrSourceRevisionNotValidated); !errors.Is(got, assetcatalog.ErrSourceRevisionNotValidated) {
		t.Fatalf("mapSourceRevisionError(sentinel) = %v", got)
	}
}

func TestMapSourceRevisionErrorTargetsOnlyNotValidatedConstraints(t *testing.T) {
	err := &pgconn.PgError{Code: "55000", ConstraintName: "asset_source_revisions_validation_guard"}
	if got := mapSourceRevisionError(err); !errors.Is(got, assetcatalog.ErrSourceRevisionNotValidated) {
		t.Errorf("validation constraint mapped to %v", got)
	}
	for _, constraint := range []string{
		"asset_source_revisions_publication_closure_guard",
		"asset_sources_version_guard",
	} {
		err := &pgconn.PgError{Code: "55000", ConstraintName: constraint}
		if got := mapSourceRevisionError(err); errors.Is(got, assetcatalog.ErrSourceRevisionNotValidated) {
			t.Fatalf("unrelated constraint %s mapped to not-validated: %v", constraint, got)
		}
	}
}

func TestMapSourceRevisionErrorClassifiesKnownVersionAndStateConstraints(t *testing.T) {
	for _, constraint := range []string{
		"asset_source_revisions_source_version_guard",
		"asset_source_revisions_version_guard",
		"asset_sources_version_guard",
	} {
		err := &pgconn.PgError{Code: "55000", ConstraintName: constraint}
		if got := mapSourceRevisionError(err); !errors.Is(got, assetcatalog.ErrVersionConflict) {
			t.Errorf("version constraint %s mapped to %v", constraint, got)
		}
	}
	for _, constraint := range []string{
		"asset_source_revisions_state_guard",
		"asset_source_revisions_sequence_guard",
		"asset_source_revisions_new_validation_run_guard",
		"asset_sources_gate_transition_guard",
		"asset_sources_validating_gate_guard",
		"asset_source_runs_cancel_guard",
	} {
		err := &pgconn.PgError{Code: "55000", ConstraintName: constraint}
		if got := mapSourceRevisionError(err); !errors.Is(got, assetcatalog.ErrStateConflict) {
			t.Errorf("state constraint %s mapped to %v", constraint, got)
		}
	}
}

func TestMapSourceRevisionErrorClassifiesOnlyNonterminalRunUniqueConflict(t *testing.T) {
	err := &pgconn.PgError{
		Code:           "23505",
		ConstraintName: "asset_source_runs_nonterminal_uk",
	}
	if got := mapSourceRevisionError(err); !errors.Is(got, assetcatalog.ErrStateConflict) {
		t.Fatalf("nonterminal run unique constraint mapped to %v", got)
	}
	unrelated := &pgconn.PgError{
		Code:           "23505",
		ConstraintName: "unrelated_unique_constraint",
	}
	if got := mapSourceRevisionError(unrelated); errors.Is(got, assetcatalog.ErrStateConflict) {
		t.Fatalf("unrelated unique constraint mapped to state conflict: %v", got)
	}
}

func TestSourceRevisionCommandHashBindsCASAndSafeSemanticFields(t *testing.T) {
	command := assetcatalog.CreateSourceRevisionCommand{
		SourceID:                "60000000-0000-4000-8000-000000000001",
		SourceProfileID:         assetcatalog.SourceProfileIDManualV1,
		AuthorityEnvironmentIDs: []string{"30000000-0000-4000-8000-000000000001"},
		ChangeReasonCode:        "SOURCE_CONFIGURATION_CHANGED",
		ExpectedSourceVersion:   7,
	}
	first, err := createSourceRevisionCommandHash(
		assetcatalog.SourceScope{
			TenantID:    "10000000-0000-4000-8000-000000000001",
			WorkspaceID: "20000000-0000-4000-8000-000000000001",
		},
		command,
	)
	if err != nil {
		t.Fatal(err)
	}
	again, err := createSourceRevisionCommandHash(
		assetcatalog.SourceScope{
			TenantID:    "10000000-0000-4000-8000-000000000001",
			WorkspaceID: "20000000-0000-4000-8000-000000000001",
		},
		command,
	)
	if err != nil || again != first {
		t.Fatalf("stable command hash = %q, %v; want %q", again, err, first)
	}
	command.ExpectedSourceVersion++
	changed, err := createSourceRevisionCommandHash(
		assetcatalog.SourceScope{
			TenantID:    "10000000-0000-4000-8000-000000000001",
			WorkspaceID: "20000000-0000-4000-8000-000000000001",
		},
		command,
	)
	if err != nil || changed == first {
		t.Fatalf("CAS mutation hash = %q, %v; want different from %q", changed, err, first)
	}
}

func TestSourceRevisionCommandHashNormalizesAuthorityOrder(t *testing.T) {
	scope := assetcatalog.SourceScope{
		TenantID:    "10000000-0000-4000-8000-000000000001",
		WorkspaceID: "20000000-0000-4000-8000-000000000001",
	}
	command := assetcatalog.CreateSourceRevisionCommand{
		SourceID:        "60000000-0000-4000-8000-000000000001",
		SourceProfileID: assetcatalog.SourceProfileIDManualV1,
		AuthorityEnvironmentIDs: []string{
			"30000000-0000-4000-8000-000000000002",
			"30000000-0000-4000-8000-000000000001",
		},
		ChangeReasonCode:      "SOURCE_CONFIGURATION_CHANGED",
		ExpectedSourceVersion: 7,
	}
	first, err := createSourceRevisionCommandHash(scope, command)
	if err != nil {
		t.Fatal(err)
	}
	command.AuthorityEnvironmentIDs[0], command.AuthorityEnvironmentIDs[1] =
		command.AuthorityEnvironmentIDs[1], command.AuthorityEnvironmentIDs[0]
	second, err := createSourceRevisionCommandHash(scope, command)
	if err != nil || second != first {
		t.Fatalf("authority-order hashes = %q / %q, error = %v", first, second, err)
	}
}

func TestCreateSourceCommandHashBindsSelectorNameScopeAndCanonicalAuthorities(t *testing.T) {
	scope := assetcatalog.SourceScope{
		TenantID:    "10000000-0000-4000-8000-000000000001",
		WorkspaceID: "20000000-0000-4000-8000-000000000001",
	}
	command := assetcatalog.CreateSourceCommand{
		Name:            "manual source",
		SourceProfileID: assetcatalog.SourceProfileIDManualV1,
		AuthorityEnvironmentIDs: []string{
			"30000000-0000-4000-8000-000000000002",
			"30000000-0000-4000-8000-000000000001",
		},
	}
	first, err := createSourceCommandHash(scope, command)
	if err != nil {
		t.Fatal(err)
	}
	command.AuthorityEnvironmentIDs[0], command.AuthorityEnvironmentIDs[1] =
		command.AuthorityEnvironmentIDs[1], command.AuthorityEnvironmentIDs[0]
	reordered, err := createSourceCommandHash(scope, command)
	if err != nil || reordered != first {
		t.Fatalf("authority-order hashes = %q / %q, error = %v", first, reordered, err)
	}
	command.Name = "changed source"
	changed, err := createSourceCommandHash(scope, command)
	if err != nil || changed == first {
		t.Fatalf("name mutation hash = %q, %v; want different from %q", changed, err, first)
	}
	command.Name = "manual source"
	command.SourceProfileID = "future-v1"
	changed, err = createSourceCommandHash(scope, command)
	if err != nil || changed == first {
		t.Fatalf("selector mutation hash = %q, %v; want different from %q", changed, err, first)
	}
}

func TestRequestSyncSourceKindRejectsManualCSVAndControlPlaneAPI(t *testing.T) {
	for _, kind := range []assetcatalog.SourceKind{
		assetcatalog.SourceKindManual,
		assetcatalog.SourceKindCSVImport,
		assetcatalog.SourceKindControlPlaneAPI,
	} {
		if requestSyncSourceKindAllowed(kind) {
			t.Errorf("request sync admitted %s", kind)
		}
	}
	if !requestSyncSourceKindAllowed(assetcatalog.SourceKindExternalCMDB) {
		t.Fatal("request sync rejected real external source")
	}
}

func TestExactManualRevisionProfileRejectsSemanticDrift(t *testing.T) {
	profile, err := assetcatalog.NewBuiltinSourceProfileAdmissionResolver().
		ResolveProfileAdmission(t.Context(), "MANUAL_V1")
	if err != nil {
		t.Fatal(err)
	}
	authorities := []string{"30000000-0000-4000-8000-000000000001"}
	authorityDigest, err := assetcatalog.AuthorityScopeDigest(authorities)
	if err != nil {
		t.Fatal(err)
	}
	definitionDigest, err := manualSourceDefinitionDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	source := assetcatalog.Source{
		Kind:         assetcatalog.SourceKindManual,
		ProviderKind: profile.ProviderKind,
		Status:       assetcatalog.SourceStatusActive,
	}
	revision := assetcatalog.SourceRevision{
		Status:                        assetcatalog.SourceRevisionValidated,
		CanonicalProfileManifest:      append([]byte(nil), profile.CanonicalProfileManifest...),
		ProfileManifestSHA256:         profile.ProfileManifestSHA256,
		CanonicalProviderSchema:       append([]byte(nil), profile.CanonicalProviderSchema...),
		CanonicalProviderSchemaSHA256: profile.CanonicalProviderSchemaSHA256,
		IntegrationID:                 profile.IntegrationID,
		SyncMode:                      profile.SyncMode,
		CredentialReferenceID:         profile.CredentialReferenceID,
		TrustReferenceID:              profile.TrustReferenceID,
		NetworkPolicyReferenceID:      profile.NetworkPolicyReferenceID,
		AuthorityEnvironmentIDs:       authorities,
		AuthorityScopeDigest:          authorityDigest,
		RateLimitRequests:             profile.RateLimitRequests,
		RateLimitWindowSeconds:        profile.RateLimitWindowSeconds,
		BackpressureBaseSeconds:       profile.BackpressureBaseSeconds,
		BackpressureMaxSeconds:        profile.BackpressureMaxSeconds,
		ProfileCode:                   profile.ProfileCode,
		ScheduleExpression:            profile.ScheduleExpression,
		TypedExtensionCode:            profile.TypedExtensionCode,
		PreparedExtensionDigest:       profile.PreparedExtensionDigest,
		SourceDefinitionDigest:        definitionDigest,
	}
	if !exactManualRevisionProfile(source, revision, profile) {
		t.Fatal("exact MANUAL profile was rejected")
	}
	if err := admitSourceRevisionPublication(t.Context(), source, revision); err != nil {
		t.Fatalf("exact MANUAL publication admission error = %v", err)
	}
	revision.CanonicalProfileManifest[len(revision.CanonicalProfileManifest)-1] ^= 1
	if exactManualRevisionProfile(source, revision, profile) {
		t.Fatal("semantic profile drift was admitted")
	}
	if err := admitSourceRevisionPublication(t.Context(), source, revision); !errors.Is(
		err, assetcatalog.ErrStateConflict,
	) {
		t.Fatalf("drifted MANUAL publication admission error = %v", err)
	}
	source.Kind = assetcatalog.SourceKindExternalCMDB
	if err := admitSourceRevisionPublication(t.Context(), source, revision); !errors.Is(
		err, assetcatalog.ErrUnavailable,
	) {
		t.Fatalf("unsupported external publication admission error = %v", err)
	}
}

func TestSourceRunBlocksPublicationOnlyAfterClaim(t *testing.T) {
	if sourceRunBlocksPublication(nil) {
		t.Fatal("nil nonterminal run blocked publication")
	}
	for _, status := range []assetcatalog.RunStatus{
		assetcatalog.RunStatusQueued,
		assetcatalog.RunStatusDelayed,
	} {
		if sourceRunBlocksPublication(&nonterminalSourceRun{Status: status}) {
			t.Errorf("%s run blocked publication before publish-close cancellation", status)
		}
	}
	for _, status := range []assetcatalog.RunStatus{
		assetcatalog.RunStatusRunning,
		assetcatalog.RunStatusFinalizing,
	} {
		if !sourceRunBlocksPublication(&nonterminalSourceRun{Status: status}) {
			t.Errorf("%s run did not fail closed", status)
		}
	}
}

func TestSourceMutationAuditAndOutboxShapesCannotCarryProfileOrOpaqueFacts(t *testing.T) {
	for _, testCase := range []struct {
		value    any
		expected map[string]reflect.Type
	}{
		{
			value: sourceMutationAuditDetails{},
			expected: map[string]reflect.Type{
				"CommandSHA256": reflect.TypeOf(""),
				"SourceID":      reflect.TypeOf(""),
				"ReasonCode":    reflect.TypeOf(""),
				"Revision":      reflect.TypeOf(int64(0)),
				"RunID":         reflect.TypeOf(""),
				"SourceVersion": reflect.TypeOf(int64(0)),
				"RevisionVersion": reflect.TypeOf(
					int64(0),
				),
				"RunVersion": reflect.TypeOf(int64(0)),
			},
		},
		{
			value: sourceOutboxPayload{},
			expected: map[string]reflect.Type{
				"SourceID":        reflect.TypeOf(""),
				"Revision":        reflect.TypeOf(int64(0)),
				"RunID":           reflect.TypeOf(""),
				"SourceVersion":   reflect.TypeOf(int64(0)),
				"RevisionVersion": reflect.TypeOf(int64(0)),
				"RunVersion":      reflect.TypeOf(int64(0)),
				"TraceID":         reflect.TypeOf(""),
			},
		},
	} {
		value := testCase.value
		typ := reflect.TypeOf(value)
		if typ.NumField() != len(testCase.expected) {
			t.Fatalf("%s field count = %d, want exact safe field count %d",
				typ.Name(), typ.NumField(), len(testCase.expected))
		}
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			wantType, found := testCase.expected[field.Name]
			if !found || field.Type != wantType {
				t.Errorf("%s.%s = %s, want exact safe field/type %v",
					typ.Name(), field.Name, field.Type, wantType)
			}
			name := strings.ToLower(field.Name)
			for _, forbidden := range []string{
				"profile", "manifest", "schema", "credential", "trust", "network",
				"endpoint", "header", "body", "secret", "canonical",
			} {
				if strings.Contains(name, forbidden) {
					t.Errorf("%s.%s exposes forbidden persisted side-effect field",
						typ.Name(), field.Name)
				}
			}
		}
	}
}
