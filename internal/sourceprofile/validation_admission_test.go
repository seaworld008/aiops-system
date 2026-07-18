package sourceprofile_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/sourceprofile"
)

const exactRuntimeAdmissionManifest = `{"schema_version":"discovery-worker-runtime-admission.v1","providers":[{"provider_kind":"CMDB_CATALOG_V1","profile_code":"CMDB_CATALOG_V1","canonical_descriptor_digest":"04a55074842e641d87ad67c42f1020b9b097ad15c3e781aaeffa3887837fdd08","runtime_recovery_capability_digest":"92f56dca945425f4129703183c71ba9c0aa08f47c3f8e8ec2ed6cdea2951f5aa"}]}`

func TestValidationAdmissionAdmitsOnlyExactCMDBProfileRuntimeAndGate(t *testing.T) {
	descriptor, manifest, request := exactValidationAdmissionFixture(t)
	admission, err := sourceprofile.NewSourceValidationRuntimeAdmission(descriptor, manifest)
	if err != nil {
		t.Fatalf("NewSourceValidationRuntimeAdmission() error = %v", err)
	}
	if err := admission.Admit(context.Background(), request); err != nil {
		t.Fatalf("Admit(exact CMDB closure) error = %v", err)
	}
}

func TestValidationAdmissionSupportsFreshReplayAndPublishClosedLifecycle(t *testing.T) {
	descriptor, manifest, request := exactValidationAdmissionFixture(t)
	admission, err := sourceprofile.NewSourceValidationRuntimeAdmission(descriptor, manifest)
	if err != nil {
		t.Fatal(err)
	}
	runID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	proofDigest := strings.Repeat("a", 64)
	tests := []struct {
		name   string
		mutate func(*sourceprofile.SourceValidationAdmissionRequest)
	}{
		{name: "fresh draft"},
		{
			name: "validating replay",
			mutate: func(value *sourceprofile.SourceValidationAdmissionRequest) {
				value.Revision.Status = assetcatalog.SourceRevisionValidating
				value.Revision.ValidationRunID = runID
				value.Source.GateStatus = assetcatalog.SourceGateValidating
				value.Source.GateReasonCode = "VALIDATION_IN_PROGRESS"
				value.Source.GateRevision = 1
				value.Source.ValidatedRunID = runID
			},
		},
		{
			name: "validated publication",
			mutate: func(value *sourceprofile.SourceValidationAdmissionRequest) {
				value.Revision.Status = assetcatalog.SourceRevisionValidated
				value.Revision.ValidationRunID = runID
				value.Revision.ValidationDigest = proofDigest
				value.Source.GateStatus = assetcatalog.SourceGateValidating
				value.Source.GateReasonCode = "VALIDATION_IN_PROGRESS"
				value.Source.GateRevision = 1
				value.Source.ValidatedRunID = runID
			},
		},
		{
			name: "published closed replay",
			mutate: func(value *sourceprofile.SourceValidationAdmissionRequest) {
				value.Revision.Status = assetcatalog.SourceRevisionPublished
				value.Revision.ValidationRunID = runID
				value.Revision.ValidationDigest = proofDigest
				value.Source.GateReasonCode = "PUBLISHED_VALIDATION_REFERENCE_DRIFT"
				value.Source.GateRevision = 2
				value.Source.PublishedRevision = value.Revision.Revision
				value.Source.PublishedRevisionDigest = value.Revision.CanonicalRevisionDigest
				value.Source.CheckpointSourceRevision = value.Revision.Revision
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := request.Clone()
			if test.mutate != nil {
				test.mutate(&candidate)
			}
			if err := admission.Admit(t.Context(), candidate); err != nil {
				t.Fatalf("Admit(%s) error = %v", test.name, err)
			}
		})
	}
}

func TestValidationAdmissionImportBoundaryExcludesProviderNetworkGraph(t *testing.T) {
	packages, err := parser.ParseDir(
		token.NewFileSet(),
		".",
		nil,
		parser.ImportsOnly,
	)
	if err != nil {
		t.Fatalf("parse internal/sourceprofile imports: %v", err)
	}
	for packageName, parsedPackage := range packages {
		for fileName, file := range parsedPackage.Files {
			for _, imported := range file.Imports {
				path, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range []string{
					"net/http",
					"github.com/seaworld008/aiops-system/internal/assetsource/externalcmdb",
					"github.com/seaworld008/aiops-system/internal/discoveryruntime",
					"github.com/seaworld008/aiops-system/internal/discoveryworker",
				} {
					if path == forbidden {
						t.Errorf("%s/%s imports forbidden dependency %q",
							packageName, fileName, path)
					}
				}
			}
		}
	}
}

func TestValidationAdmissionRejectsMissingOrDriftedDescriptorManifestBindingAndPrerequisite(t *testing.T) {
	descriptor, manifest, request := exactValidationAdmissionFixture(t)
	tests := []struct {
		name       string
		descriptor sourceprofile.ExternalCMDBDescriptor
		manifest   sourceprofile.SourceValidationRuntimeManifest
		request    sourceprofile.SourceValidationAdmissionRequest
	}{
		{
			name: "missing descriptor", descriptor: sourceprofile.ExternalCMDBDescriptor{},
			manifest: manifest, request: request,
		},
		{
			name: "missing runtime manifest", descriptor: descriptor,
			manifest: sourceprofile.SourceValidationRuntimeManifest{}, request: request,
		},
		{
			name: "runtime manifest digest drift", descriptor: descriptor,
			manifest: sourceprofile.SourceValidationRuntimeManifest{
				CanonicalJSON: manifest.CanonicalJSON,
				DigestSHA256:  strings.Repeat("f", 64),
			},
			request: request,
		},
		{
			name: "runtime descriptor row drift", descriptor: descriptor,
			manifest: driftRuntimeDescriptorDigest(manifest), request: request,
		},
		{
			name: "runtime recovery capability row drift", descriptor: descriptor,
			manifest: driftRuntimeRecoveryCapabilityDigest(manifest), request: request,
		},
		{
			name: "revision binding drift", descriptor: descriptor, manifest: manifest,
			request: mutateValidationAdmissionRequest(request, func(value *sourceprofile.SourceValidationAdmissionRequest) {
				value.Revision.CanonicalRevisionDigest = strings.Repeat("f", 64)
			}),
		},
		{
			name: "installed profile drift", descriptor: descriptor, manifest: manifest,
			request: mutateValidationAdmissionRequest(request, func(value *sourceprofile.SourceValidationAdmissionRequest) {
				value.Profile.NetworkPolicyReferenceID = "49999999-9999-4999-8999-999999999999"
			}),
		},
		{
			name: "source gate prerequisite drift", descriptor: descriptor, manifest: manifest,
			request: mutateValidationAdmissionRequest(request, func(value *sourceprofile.SourceValidationAdmissionRequest) {
				value.Source.GateStatus = assetcatalog.SourceGateSuspended
				value.Source.GateReasonCode = "CLEANUP_UNCERTAIN"
			}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admission, err := sourceprofile.NewSourceValidationRuntimeAdmission(
				test.descriptor,
				test.manifest,
			)
			if err == nil {
				err = admission.Admit(context.Background(), test.request)
			}
			if !errors.Is(err, assetcatalog.ErrUnavailable) {
				t.Fatalf("validation admission error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func exactValidationAdmissionFixture(t *testing.T) (
	sourceprofile.ExternalCMDBDescriptor,
	sourceprofile.SourceValidationRuntimeManifest,
	sourceprofile.SourceValidationAdmissionRequest,
) {
	t.Helper()
	descriptor := sourceprofile.ExternalCMDBV1()
	references := sourceprofile.ExternalCMDBProfileReferences{
		IntegrationID:            "44444444-4444-4444-8444-444444444444",
		CredentialReferenceID:    "55555555-5555-4555-8555-555555555555",
		TrustReferenceID:         "66666666-6666-4666-8666-666666666666",
		NetworkPolicyReferenceID: "77777777-7777-4777-8777-777777777777",
	}
	registration, err := descriptor.Registration(references)
	if err != nil {
		t.Fatalf("External CMDB Registration() error = %v", err)
	}
	registry, err := assetcatalog.NewSourceProfileRegistry(registration)
	if err != nil {
		t.Fatalf("NewSourceProfileRegistry() error = %v", err)
	}
	profile, err := registry.Resolve(sourceprofile.ExternalCMDBProfileSelector)
	if err != nil {
		t.Fatalf("Resolve(external CMDB) error = %v", err)
	}
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	source := assetcatalog.Source{
		ID:           "11111111-1111-4111-8111-111111111111",
		TenantID:     "22222222-2222-4222-8222-222222222222",
		WorkspaceID:  "33333333-3333-4333-8333-333333333333",
		ProviderKind: descriptor.ProviderKind(),
		Name:         "external cmdb",
		Kind:         descriptor.SourceKind(),
		Status:       assetcatalog.SourceStatusActive,
		GateStatus:   assetcatalog.SourceGateUnavailable,
		Version:      1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	authorityIDs := []string{"88888888-8888-4888-8888-888888888888"}
	authorityDigest, err := assetcatalog.AuthorityScopeDigest(authorityIDs)
	if err != nil {
		t.Fatalf("AuthorityScopeDigest() error = %v", err)
	}
	revision := assetcatalog.SourceRevision{
		ID:                            "99999999-9999-4999-8999-999999999999",
		SourceID:                      source.ID,
		TenantID:                      source.TenantID,
		WorkspaceID:                   source.WorkspaceID,
		Revision:                      1,
		Status:                        assetcatalog.SourceRevisionDraft,
		CanonicalProfileManifest:      profile.CanonicalProfileManifest,
		CanonicalProviderSchema:       profile.CanonicalProviderSchema,
		ProfileManifestSHA256:         profile.ProfileManifestSHA256,
		CanonicalProviderSchemaSHA256: profile.CanonicalProviderSchemaSHA256,
		IntegrationID:                 profile.IntegrationID,
		SyncMode:                      profile.SyncMode,
		CredentialReferenceID:         profile.CredentialReferenceID,
		TrustReferenceID:              profile.TrustReferenceID,
		NetworkPolicyReferenceID:      profile.NetworkPolicyReferenceID,
		AuthorityEnvironmentIDs:       authorityIDs,
		AuthorityScopeDigest:          authorityDigest,
		RateLimitRequests:             profile.RateLimitRequests,
		RateLimitWindowSeconds:        profile.RateLimitWindowSeconds,
		BackpressureBaseSeconds:       profile.BackpressureBaseSeconds,
		BackpressureMaxSeconds:        profile.BackpressureMaxSeconds,
		ProfileCode:                   profile.ProfileCode,
		ScheduleExpression:            profile.ScheduleExpression,
		TypedExtensionCode:            profile.TypedExtensionCode,
		PreparedExtensionDigest:       profile.PreparedExtensionDigest,
		CreatedBy:                     "operator",
		ChangeReasonCode:              "INITIAL_CREATE",
		ExpectedSourceVersion:         1,
		Version:                       1,
		CreatedAt:                     now,
		UpdatedAt:                     now,
	}
	revision.SourceDefinitionDigest, err = assetcatalog.SourceDefinitionDigest(source, revision)
	if err != nil {
		t.Fatalf("SourceDefinitionDigest() error = %v", err)
	}
	revision.CanonicalRevisionDigest = revision.BindingDigest()
	if revision.CanonicalRevisionDigest == "" {
		t.Fatal("BindingDigest() is empty")
	}
	manifestDigest := sha256.Sum256([]byte(exactRuntimeAdmissionManifest))
	return descriptor, sourceprofile.SourceValidationRuntimeManifest{
			CanonicalJSON: []byte(exactRuntimeAdmissionManifest),
			DigestSHA256:  hex.EncodeToString(manifestDigest[:]),
		}, sourceprofile.SourceValidationAdmissionRequest{
			Source:   source,
			Revision: revision,
			Profile:  profile,
		}
}

func mutateValidationAdmissionRequest(
	value sourceprofile.SourceValidationAdmissionRequest,
	mutate func(*sourceprofile.SourceValidationAdmissionRequest),
) sourceprofile.SourceValidationAdmissionRequest {
	value.Revision = value.Revision.Clone()
	value.Profile = value.Profile.Clone()
	mutate(&value)
	return value
}

func driftRuntimeDescriptorDigest(
	manifest sourceprofile.SourceValidationRuntimeManifest,
) sourceprofile.SourceValidationRuntimeManifest {
	canonical := strings.Replace(
		string(manifest.CanonicalJSON),
		sourceprofile.ExternalCMDBV1().DigestSHA256(),
		strings.Repeat("e", 64),
		1,
	)
	digest := sha256.Sum256([]byte(canonical))
	return sourceprofile.SourceValidationRuntimeManifest{
		CanonicalJSON: []byte(canonical),
		DigestSHA256:  hex.EncodeToString(digest[:]),
	}
}

func driftRuntimeRecoveryCapabilityDigest(
	manifest sourceprofile.SourceValidationRuntimeManifest,
) sourceprofile.SourceValidationRuntimeManifest {
	canonical := strings.Replace(
		string(manifest.CanonicalJSON),
		"92f56dca945425f4129703183c71ba9c0aa08f47c3f8e8ec2ed6cdea2951f5aa",
		strings.Repeat("e", 64),
		1,
	)
	digest := sha256.Sum256([]byte(canonical))
	return sourceprofile.SourceValidationRuntimeManifest{
		CanonicalJSON: []byte(canonical),
		DigestSHA256:  hex.EncodeToString(digest[:]),
	}
}
