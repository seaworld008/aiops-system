package vsphere

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/vmware/govmomi/vim25/types"
)

var (
	apiVersionPattern      = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}$`)
	privilegeCodePattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]{0,127}$`)
	lowercaseDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

	requiredReadPrivileges = []string{
		"System.Anonymous",
		"System.Read",
		"System.View",
	}
)

type provider struct {
	factory ClientFactory
}

func New(factory ClientFactory) (discoverysource.Provider, error) {
	if factory.binding.ProviderKind != providerKind ||
		factory.binding.ProfileCode != profileCode ||
		factory.binding.RevisionStatus != assetcatalog.SourceRevisionValidating &&
			factory.binding.RevisionStatus != assetcatalog.SourceRevisionPublished {
		return nil, providerError("FACTORY_REJECTED")
	}
	return &provider{factory: factory}, nil
}

func (*provider) Kind() assetcatalog.SourceKind {
	return assetcatalog.SourceKindVSphere
}

func (*provider) ProviderKind() string {
	return providerKind
}

func (value *provider) Validate(
	ctx context.Context,
	runtime discoverysource.BoundRuntime,
	request discoverysource.ValidationRequest,
) (proof discoverysource.ValidationProof, returnedErr error) {
	if value == nil {
		return discoverysource.ValidationProof{}, providerError("INACTIVE_PROVIDER")
	}
	if err := request.Validate(); err != nil {
		return discoverysource.ValidationProof{}, err
	}
	if !validationRequestMatchesBinding(request, value.factory.binding) {
		return discoverysource.ValidationProof{}, providerError("VALIDATION_BINDING_REJECTED")
	}

	opened, err := value.factory.open(ctx, runtime)
	if err != nil {
		if contextErr := callerContextError(ctx); contextErr != nil {
			return discoverysource.ValidationProof{}, contextErr
		}
		if failure, mapped := validationFailureForClientError(err); mapped {
			return failure, nil
		}
		return discoverysource.ValidationProof{}, err
	}
	defer opened.authority.Clear()
	defer func() {
		cleanupContext := context.WithoutCancel(ctx)
		if closeErr := opened.client.Close(cleanupContext); closeErr != nil {
			proof = discoverysource.ValidationProof{}
			returnedErr = providerError("SESSION_CLOSE_FAILED")
		}
	}()
	if contextErr := callerContextError(ctx); contextErr != nil {
		return discoverysource.ValidationProof{}, contextErr
	}

	identity := opened.client.Identity()
	if !validVCenterIdentity(identity, opened.authority) {
		return validationFailure(
			discoverysource.ValidationCheckIdentity,
			"IDENTITY_REJECTED",
			"AUTHORITY_REJECTED",
		), nil
	}
	peerDigest := opened.client.TLSPeerDigest()
	if !lowercaseDigestPattern.MatchString(peerDigest) {
		return validationFailure(
			discoverysource.ValidationCheckTrustOrSignature,
			"TRUST_OR_SIGNATURE_REJECTED",
			"VALIDATION_REJECTED",
		), nil
	}

	currentSession, err := opened.client.CurrentSession(ctx)
	if contextErr := callerContextError(ctx); contextErr != nil {
		return discoverysource.ValidationProof{}, contextErr
	}
	if err != nil || !safeRuntimeText(currentSession.UserName, 1, 256) {
		return validationFailure(
			discoverysource.ValidationCheckCredentialOpen,
			"CREDENTIAL_OPEN_REJECTED",
			"VALIDATION_REJECTED",
		), nil
	}

	privileges, err := opened.client.EffectivePrivileges(
		ctx,
		opened.authority.roots,
		currentSession.UserName,
	)
	if contextErr := callerContextError(ctx); contextErr != nil {
		return discoverysource.ValidationProof{}, contextErr
	}
	if err != nil {
		return discoverysource.ValidationProof{}, providerError("PRIVILEGE_QUERY_FAILED")
	}
	privilegeResult := validatePrivilegeSnapshots(opened.authority.roots, privileges)
	if !privilegeResult.Valid {
		return validationFailure(
			discoverysource.ValidationCheckFixedProbe,
			"FIXED_PROBE_REJECTED",
			"VALIDATION_REJECTED",
		), nil
	}

	probe, err := opened.client.ProbeRoots(ctx, opened.authority.roots)
	if contextErr := callerContextError(ctx); contextErr != nil {
		return discoverysource.ValidationProof{}, contextErr
	}
	if err != nil {
		return discoverysource.ValidationProof{}, providerError("PROPERTY_PROBE_FAILED")
	}
	probeDigest, ok := validateRootProbe(opened.authority.roots, probe)
	if !ok {
		return validationFailure(
			discoverysource.ValidationCheckFixedProbe,
			"FIXED_PROBE_REJECTED",
			"VALIDATION_REJECTED",
		), nil
	}

	return successfulValidationProof(
		request,
		identity,
		opened.authority,
		peerDigest,
		privilegeResult,
		probeDigest,
	), nil
}

func callerContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func (value *provider) Discover(
	ctx context.Context,
	runtime discoverysource.BoundRuntime,
	request discoverysource.DiscoverRequest,
) (discoverysource.DiscoverOutcome, error) {
	return value.discover(ctx, runtime, request)
}

func validationRequestMatchesBinding(
	request discoverysource.ValidationRequest,
	binding discoverysource.RuntimeBinding,
) bool {
	return binding.RevisionStatus == assetcatalog.SourceRevisionValidating &&
		request.Locator == binding.Locator &&
		request.SourceRevision == binding.SourceRevision &&
		request.SourceRevisionDigest == binding.SourceRevisionDigest
}

func validationFailureForClientError(
	err error,
) (discoverysource.ValidationProof, bool) {
	switch clientErrorStage(err) {
	case clientFailureIdentity:
		return validationFailure(
			discoverysource.ValidationCheckIdentity,
			"IDENTITY_REJECTED",
			"AUTHORITY_REJECTED",
		), true
	case clientFailureTrust:
		return validationFailure(
			discoverysource.ValidationCheckTrustOrSignature,
			"TRUST_OR_SIGNATURE_REJECTED",
			"VALIDATION_REJECTED",
		), true
	case clientFailureNetwork:
		return validationFailure(
			discoverysource.ValidationCheckNetwork,
			"NETWORK_REJECTED",
			"VALIDATION_REJECTED",
		), true
	case clientFailureCredential:
		return validationFailure(
			discoverysource.ValidationCheckCredentialOpen,
			"CREDENTIAL_OPEN_REJECTED",
			"VALIDATION_REJECTED",
		), true
	default:
		return discoverysource.ValidationProof{}, false
	}
}

func validVCenterIdentity(
	identity vcenterIdentity,
	authority authoritySnapshot,
) bool {
	return identity.APIType == "VirtualCenter" &&
		identity.InstanceUUID == authority.instanceUUID &&
		instanceUUIDPattern.MatchString(identity.InstanceUUID) &&
		apiVersionPattern.MatchString(identity.APIVersion) &&
		authority.valid()
}

type privilegeValidation struct {
	Valid        bool
	WarningCount int64
	Digest       string
}

func validatePrivilegeSnapshots(
	roots []types.ManagedObjectReference,
	snapshots []entityPrivilegeSnapshot,
) privilegeValidation {
	if len(roots) == 0 || len(snapshots) != len(roots) {
		return privilegeValidation{}
	}
	expectedRoots := slices.Clone(roots)
	slices.SortFunc(expectedRoots, compareManagedObjectReference)
	owned := make([]entityPrivilegeSnapshot, len(snapshots))
	for index, snapshot := range snapshots {
		owned[index] = entityPrivilegeSnapshot{
			Entity:     snapshot.Entity,
			Privileges: slices.Clone(snapshot.Privileges),
		}
		slices.Sort(owned[index].Privileges)
	}
	slices.SortFunc(owned, func(left, right entityPrivilegeSnapshot) int {
		return compareManagedObjectReference(left.Entity, right.Entity)
	})

	fields := []string{"vsphere-privilege-set.v1"}
	var warnings int64
	for index, snapshot := range owned {
		if compareManagedObjectReference(snapshot.Entity, expectedRoots[index]) != 0 ||
			len(snapshot.Privileges) == 0 {
			return privilegeValidation{}
		}
		fields = append(fields, snapshot.Entity.Type, snapshot.Entity.Value)
		for privilegeIndex, privilege := range snapshot.Privileges {
			if !privilegeCodePattern.MatchString(privilege) ||
				privilegeIndex > 0 && snapshot.Privileges[privilegeIndex-1] == privilege {
				return privilegeValidation{}
			}
			fields = append(fields, privilege)
			if !slices.Contains(requiredReadPrivileges, privilege) {
				warnings++
			}
		}
		for _, required := range requiredReadPrivileges {
			if !slices.Contains(snapshot.Privileges, required) {
				return privilegeValidation{}
			}
		}
	}
	return privilegeValidation{
		Valid:        true,
		WarningCount: warnings,
		Digest:       digestFramedStrings(fields...),
	}
}

func validateRootProbe(
	roots []types.ManagedObjectReference,
	probe rootProbeResult,
) (string, bool) {
	if len(roots) == 0 || len(probe.Objects) != len(roots) {
		return "", false
	}
	expected := slices.Clone(roots)
	slices.SortFunc(expected, compareManagedObjectReference)
	objects := slices.Clone(probe.Objects)
	slices.SortFunc(objects, func(left, right rootProbeObject) int {
		return compareManagedObjectReference(left.Reference, right.Reference)
	})
	fields := []string{"vsphere-fixed-root-probe.v1"}
	for index, object := range objects {
		if compareManagedObjectReference(object.Reference, expected[index]) != 0 ||
			!safeRuntimeText(object.Name, 1, 256) ||
			sensitiveRuntimeText(object.Name) {
			return "", false
		}
		fields = append(fields, object.Reference.Type, object.Reference.Value, object.Name)
	}
	return digestFramedStrings(fields...), true
}

func validationFailure(
	kind discoverysource.ValidationCheckKind,
	checkCode string,
	proofCode string,
) discoverysource.ValidationProof {
	return discoverysource.ValidationProof{
		Outcome: assetcatalog.ValidationOutcomeFailed,
		Code:    proofCode,
		Checks: []discoverysource.ValidationCheck{{
			Kind:   kind,
			Code:   checkCode,
			Passed: false,
		}},
	}
}

func successfulValidationProof(
	request discoverysource.ValidationRequest,
	identity vcenterIdentity,
	authority authoritySnapshot,
	peerDigest string,
	privileges privilegeValidation,
	probeDigest string,
) discoverysource.ValidationProof {
	identityDigest := digestFramedStrings(
		"vsphere-vcenter-identity.v1",
		identity.InstanceUUID,
		identity.APIVersion,
		identity.APIType,
		authority.environmentID,
		authority.rootDigest,
	)
	credentialDigest := digestFramedStrings(
		"vsphere-credential-open.v1",
		identity.InstanceUUID,
		authority.environmentID,
		authority.rootDigest,
	)
	fixedProbeDigest := digestFramedStrings(
		"vsphere-fixed-probe.v1",
		privileges.Digest,
		probeDigest,
	)
	schemaDigest := digestFramedStrings(
		"vsphere-normalized-schema.v1",
		normalizedSchemaVersion,
		strings.Join(allowedObjectTypes, "\x00"),
	)
	dlpDigest := digestFramedStrings(
		"vsphere-dlp-allowlist.v1",
		strings.Join(normalizedDocumentFieldAllowlist, "\x00"),
	)
	budgetDigest := digestFramedStrings(
		"vsphere-validation-budget.v1",
		strconv.FormatInt(request.Limits.MaxPageItems, 10),
		strconv.FormatInt(request.Limits.MaxPageRelations, 10),
		strconv.FormatInt(request.Limits.MaxPageBytes, 10),
		strconv.FormatInt(request.Limits.MaxDocumentBytes, 10),
		strconv.Itoa(len(authority.roots)),
	)
	return discoverysource.ValidationProof{
		Outcome: assetcatalog.ValidationOutcomeSucceeded,
		Code:    "VALIDATION_SUCCEEDED",
		Checks: []discoverysource.ValidationCheck{
			{
				Kind:         discoverysource.ValidationCheckIdentity,
				Code:         "IDENTITY_VERIFIED",
				Passed:       true,
				Count:        1,
				DigestSHA256: identityDigest,
			},
			{
				Kind:         discoverysource.ValidationCheckTrustOrSignature,
				Code:         "TRUST_OR_SIGNATURE_VERIFIED",
				Passed:       true,
				Count:        1,
				DigestSHA256: peerDigest,
			},
			{
				Kind:   discoverysource.ValidationCheckNetwork,
				Code:   "NETWORK_VERIFIED",
				Passed: true,
				Count:  1,
			},
			{
				Kind:         discoverysource.ValidationCheckCredentialOpen,
				Code:         "CREDENTIAL_OPEN_VERIFIED",
				Passed:       true,
				Count:        1,
				DigestSHA256: credentialDigest,
			},
			{
				Kind:         discoverysource.ValidationCheckFixedProbe,
				Code:         "FIXED_PROBE_VERIFIED",
				Passed:       true,
				Count:        privileges.WarningCount,
				DigestSHA256: fixedProbeDigest,
			},
			{
				Kind:         discoverysource.ValidationCheckSchema,
				Code:         "SCHEMA_VERIFIED",
				Passed:       true,
				Count:        int64(len(authority.roots)),
				DigestSHA256: schemaDigest,
			},
			{
				Kind:         discoverysource.ValidationCheckDLP,
				Code:         "DLP_VERIFIED",
				Passed:       true,
				Count:        int64(len(authority.roots)),
				DigestSHA256: dlpDigest,
			},
			{
				Kind:         discoverysource.ValidationCheckBudget,
				Code:         "BUDGET_VERIFIED",
				Passed:       true,
				Count:        int64(len(authority.roots)),
				DigestSHA256: budgetDigest,
			},
		},
	}
}

var _ discoverysource.Provider = (*provider)(nil)
