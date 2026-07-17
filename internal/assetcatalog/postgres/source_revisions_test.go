package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

var _ assetcatalog.SourceRevisionRepository = (*Repository)(nil)
var _ assetcatalog.SourceProfileAdmissionResolver = (*Repository)(nil)

func TestRepositoryConsumesInjectedProfileRegistryForCreationAndAdmission(t *testing.T) {
	if _, err := NewWithSourceProfileRegistry(
		&pgxpool.Pool{},
		nil,
		func() string { return "70000000-0000-4000-8000-000000000001" },
		nil,
	); err == nil {
		t.Fatal("NewWithSourceProfileRegistry accepted nil Registry")
	}
	profile, err := assetcatalog.CSVProfileV1("csv-signature-reference-v1")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := assetcatalog.NewSourceProfileRegistry(assetcatalog.SourceProfileRegistration{
		Selector: assetcatalog.SourceProfileIDCSVRFC4180V1,
		Profile:  profile,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewWithSourceProfileRegistry(
		&pgxpool.Pool{},
		nil,
		func() string { return "70000000-0000-4000-8000-000000000001" },
		registry,
	)
	if err != nil {
		t.Fatal(err)
	}
	manual, err := repository.profiles.Resolve(assetcatalog.SourceProfileIDManualV1)
	if err != nil || manual.ProfileCode != assetcatalog.ProfileCode("MANUAL_V1") {
		t.Fatalf("extended repository registry lost manual selector: (%#v, %v)", manual, err)
	}
	manualAdmission, err := repository.ResolveProfileAdmission(t.Context(), assetcatalog.ProfileCode("MANUAL_V1"))
	if err != nil || manualAdmission.ProfileCode != assetcatalog.ProfileCode("MANUAL_V1") {
		t.Fatalf("extended repository registry lost manual admission: (%#v, %v)", manualAdmission, err)
	}
	resolved, err := repository.profiles.Resolve(assetcatalog.SourceProfileIDCSVRFC4180V1)
	if err != nil || resolved.CredentialReferenceID != profile.CredentialReferenceID {
		t.Fatalf("creation registry Resolve() = (%#v, %v)", resolved, err)
	}
	admitted, err := repository.ResolveProfileAdmission(t.Context(), assetcatalog.ProfileCode("CSV_RFC4180_V1"))
	if err != nil || admitted.CredentialReferenceID != profile.CredentialReferenceID {
		t.Fatalf("admission registry ResolveProfileAdmission() = (%#v, %v)", admitted, err)
	}
}

func TestResolveSourceProfileAfterReplayCheckPrioritizesConsumedCommandHash(t *testing.T) {
	repository := &Repository{profiles: assetcatalog.NewBuiltinSourceProfileRegistry()}
	replayChecks := 0
	_, err := repository.resolveSourceProfileAfterReplayCheck("future-v1", func() error {
		replayChecks++
		return assetcatalog.ErrIdempotency
	})
	if !errors.Is(err, assetcatalog.ErrIdempotency) || replayChecks != 1 {
		t.Fatalf("changed unknown-selector replay = (%v, checks:%d), want ErrIdempotency/1", err, replayChecks)
	}
	if _, err := repository.resolveSourceProfileAfterReplayCheck("future-v1", nil); !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("fresh unknown selector error = %v, want ErrNotFound", err)
	}
}

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

func TestSourceCreationReplayRaceOnlyAcceptsExactUniqueConstraint(t *testing.T) {
	for _, testCase := range []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "exact Source create idempotency race",
			err: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: sourceCreateIdempotencyConstraint,
			},
			want: true,
		},
		{
			name: "wrapped exact Source create idempotency race",
			err: errors.Join(errors.New("operation failed"), &pgconn.PgError{
				Code:           "23505",
				ConstraintName: sourceCreateIdempotencyConstraint,
			}),
			want: true,
		},
		{
			name: "different unique constraint",
			err: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: "asset_management_idempotency_audit_uk",
			},
		},
		{
			name: "different SQLSTATE",
			err: &pgconn.PgError{
				Code:           "23503",
				ConstraintName: sourceCreateIdempotencyConstraint,
			},
		},
		{name: "unknown error", err: errors.New("unknown database error")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := isSourceCreationReplayRace(testCase.err); got != testCase.want {
				t.Fatalf("isSourceCreationReplayRace() = %t, want %t", got, testCase.want)
			}
		})
	}
}

func TestSourceCreationSerializableReservesReceiptAttemptAfterRetryBudget(t *testing.T) {
	operationErrors := []error{
		&pgconn.PgError{Code: "40001"},
		&pgconn.PgError{Code: "40P01"},
		&pgconn.PgError{
			Code:           "23505",
			ConstraintName: sourceCreateIdempotencyConstraint,
		},
		nil,
	}
	var begins, commits, rollbacks int
	var receiptRequirements []bool
	repository := &Repository{pool: &assetCatalogPool{
		beginTx: func(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
			begins++
			if options.IsoLevel != pgx.Serializable || options.AccessMode != pgx.ReadWrite {
				t.Fatalf("Source creation transaction options = %#v", options)
			}
			return &sourceCreationRetryTx{commits: &commits, rollbacks: &rollbacks}, nil
		},
	}}
	result, err := withSourceCreationSerializable(
		context.Background(),
		repository,
		func(_ pgx.Tx, receiptRequired bool) (string, error) {
			receiptRequirements = append(receiptRequirements, receiptRequired)
			attempt := len(receiptRequirements) - 1
			if attempt >= len(operationErrors) {
				t.Fatalf("unexpected Source creation attempt %d", attempt+1)
			}
			if operationErrors[attempt] != nil {
				return "", operationErrors[attempt]
			}
			return "original receipt", nil
		},
	)
	if err != nil || result != "original receipt" {
		t.Fatalf("withSourceCreationSerializable() = (%q, %v)", result, err)
	}
	if begins != 4 || commits != 1 || rollbacks != 3 {
		t.Fatalf("Source creation transaction counts = begin:%d commit:%d rollback:%d; want 4/1/3",
			begins, commits, rollbacks)
	}
	wantRequirements := []bool{false, false, false, true}
	if !reflect.DeepEqual(receiptRequirements, wantRequirements) {
		t.Fatalf("receipt-required attempts = %v, want %v",
			receiptRequirements, wantRequirements)
	}
}

func TestSourceCreationSerializableDoesNotRetryUnrelatedErrors(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		err     error
		wantErr error
	}{
		{
			name: "different unique constraint",
			err: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: "asset_management_idempotency_audit_uk",
			},
			wantErr: assetcatalog.ErrIdempotency,
		},
		{
			name: "different SQLSTATE",
			err: &pgconn.PgError{
				Code:           "23503",
				ConstraintName: sourceCreateIdempotencyConstraint,
			},
			wantErr: assetcatalog.ErrScopeViolation,
		},
		{
			name:    "unknown error",
			err:     errors.New("unknown database error"),
			wantErr: errAssetCatalogRepositoryFailure,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var begins, commits, rollbacks int
			var receiptRequirements []bool
			repository := sourceCreationRetryRepository(
				t, &begins, &commits, &rollbacks,
			)
			_, err := withSourceCreationSerializable(
				context.Background(),
				repository,
				func(_ pgx.Tx, receiptRequired bool) (string, error) {
					receiptRequirements = append(receiptRequirements, receiptRequired)
					return "", testCase.err
				},
			)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("withSourceCreationSerializable() error = %v, want %v",
					err, testCase.wantErr)
			}
			if begins != 1 || commits != 0 || rollbacks != 1 {
				t.Fatalf("Source creation transaction counts = begin:%d commit:%d rollback:%d; want 1/0/1",
					begins, commits, rollbacks)
			}
			if !reflect.DeepEqual(receiptRequirements, []bool{false}) {
				t.Fatalf("receipt-required attempts = %v, want [false]",
					receiptRequirements)
			}
		})
	}
}

func TestSourceCreationReceiptTransactionNeverRetries(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		err     error
		wantErr error
	}{
		{
			name:    "serialization failure",
			err:     &pgconn.PgError{Code: "40001"},
			wantErr: assetcatalog.ErrStateConflict,
		},
		{
			name: "same exact unique race",
			err: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: sourceCreateIdempotencyConstraint,
			},
			wantErr: assetcatalog.ErrIdempotency,
		},
		{
			name:    "unknown error",
			err:     errors.New("unknown database error"),
			wantErr: errAssetCatalogRepositoryFailure,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var begins, commits, rollbacks int
			var receiptRequirements []bool
			repository := sourceCreationRetryRepository(
				t, &begins, &commits, &rollbacks,
			)
			_, err := withSourceCreationSerializable(
				context.Background(),
				repository,
				func(_ pgx.Tx, receiptRequired bool) (string, error) {
					receiptRequirements = append(receiptRequirements, receiptRequired)
					if !receiptRequired {
						return "", &pgconn.PgError{
							Code:           "23505",
							ConstraintName: sourceCreateIdempotencyConstraint,
						}
					}
					return "", testCase.err
				},
			)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("withSourceCreationSerializable() error = %v, want %v",
					err, testCase.wantErr)
			}
			if begins != 2 || commits != 0 || rollbacks != 2 {
				t.Fatalf("Source creation transaction counts = begin:%d commit:%d rollback:%d; want 2/0/2",
					begins, commits, rollbacks)
			}
			if !reflect.DeepEqual(receiptRequirements, []bool{false, true}) {
				t.Fatalf("receipt-required attempts = %v, want [false true]",
					receiptRequirements)
			}
		})
	}
}

func sourceCreationRetryRepository(
	t *testing.T,
	begins, commits, rollbacks *int,
) *Repository {
	t.Helper()
	return &Repository{pool: &assetCatalogPool{
		beginTx: func(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
			*begins++
			if options.IsoLevel != pgx.Serializable || options.AccessMode != pgx.ReadWrite {
				t.Fatalf("Source creation transaction options = %#v", options)
			}
			return &sourceCreationRetryTx{commits: commits, rollbacks: rollbacks}, nil
		},
	}}
}

type sourceCreationRetryTx struct {
	pgx.Tx
	commits, rollbacks *int
}

func (tx *sourceCreationRetryTx) Commit(context.Context) error {
	*tx.commits++
	return nil
}

func (tx *sourceCreationRetryTx) Rollback(context.Context) error {
	*tx.rollbacks++
	return nil
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

func TestSourceValidationRuntimeClosedOnlyForCSVRFC4180V1(t *testing.T) {
	for _, test := range []struct {
		profileCode assetcatalog.ProfileCode
		wantClosed  bool
	}{
		{profileCode: "CSV_RFC4180_V1", wantClosed: true},
		{profileCode: "MANUAL_V1", wantClosed: false},
		{profileCode: "EXTERNAL_CMDB_V1", wantClosed: false},
		{profileCode: "FUTURE_V1", wantClosed: false},
	} {
		if got := sourceValidationRuntimeClosed(test.profileCode); got != test.wantClosed {
			t.Errorf("sourceValidationRuntimeClosed(%q) = %t, want %t",
				test.profileCode, got, test.wantClosed)
		}
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
		{
			value: sourceCreationAuditDetails{},
			expected: map[string]reflect.Type{
				"CommandSHA256": reflect.TypeOf(""),
				"SourceID":      reflect.TypeOf(""),
				"OutboxID":      reflect.TypeOf(""),
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
			value: sourceCreationOutboxPayload{},
			expected: map[string]reflect.Type{
				"AuditID":         reflect.TypeOf(""),
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
