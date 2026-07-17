package assetcatalog

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/seaworld008/aiops-system/internal/authn"
)

var (
	ErrInvalidRequest  = errors.New("invalid request")
	ErrNotFound        = errors.New("not found")
	ErrScopeViolation  = errors.New("scope violation")
	ErrVersionConflict = errors.New("version conflict")
	ErrStateConflict   = errors.New("state conflict")
	ErrIdempotency     = errors.New("idempotency conflict")
	ErrUnavailable     = errors.New("asset catalog unavailable")
)

type MutationMetadata struct {
	TraceID, IdempotencyKey, RequestHash string
}

const (
	mutationScopeSource      uint8 = 1
	mutationScopeEnvironment uint8 = 2
)

type MutationContext struct {
	scopeKind       uint8
	sourceScope     SourceScope
	environmentID   string
	actorID         string
	subjectID       string
	authenticatedAt time.Time
	traceID         string
	idempotencyKey  string
	requestHash     string
}

func NewMutationContext(principal authn.Principal, scope Scope, metadata MutationMetadata) (MutationContext, error) {
	if !scope.Valid() || !validPrincipalForMutation(principal) || principal.TenantID != scope.TenantID || !validMutationMetadataValue(metadata) {
		return MutationContext{}, ErrInvalidRequest
	}
	value := MutationContext{
		scopeKind:       mutationScopeEnvironment,
		sourceScope:     SourceScope{TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID},
		environmentID:   scope.EnvironmentID,
		actorID:         "oidc:" + principal.Subject,
		subjectID:       principal.Subject,
		authenticatedAt: principal.AuthenticatedAt,
		traceID:         metadata.TraceID,
		idempotencyKey:  metadata.IdempotencyKey,
		requestHash:     metadata.RequestHash,
	}
	if err := value.Validate(); err != nil {
		return MutationContext{}, err
	}
	return value, nil
}

func NewSourceMutationContext(principal authn.Principal, scope SourceScope, metadata MutationMetadata) (MutationContext, error) {
	if !scope.Valid() || !validPrincipalForMutation(principal) || principal.TenantID != scope.TenantID || !validMutationMetadataValue(metadata) {
		return MutationContext{}, ErrInvalidRequest
	}
	value := MutationContext{
		scopeKind:       mutationScopeSource,
		sourceScope:     scope,
		actorID:         "oidc:" + principal.Subject,
		subjectID:       principal.Subject,
		authenticatedAt: principal.AuthenticatedAt,
		traceID:         metadata.TraceID,
		idempotencyKey:  metadata.IdempotencyKey,
		requestHash:     metadata.RequestHash,
	}
	if err := value.Validate(); err != nil {
		return MutationContext{}, err
	}
	return value, nil
}

func validPrincipalForMutation(principal authn.Principal) bool {
	return validUUID(principal.TenantID) && validSafeText(principal.Subject, 1, 256) &&
		validStoredTime(principal.AuthenticatedAt)
}

func validMutationMetadataValue(metadata MutationMetadata) bool {
	return validSafeToken(metadata.TraceID, 1, 256) &&
		validIdempotencyKey(metadata.IdempotencyKey) && validDigest(metadata.RequestHash)
}

func (value MutationContext) Validate() error {
	if !value.sourceScope.Valid() || !validSafeText(value.subjectID, 1, 256) ||
		value.actorID != "oidc:"+value.subjectID || !validStoredTime(value.authenticatedAt) ||
		!validSafeToken(value.traceID, 1, 256) || !validIdempotencyKey(value.idempotencyKey) ||
		!validDigest(value.requestHash) {
		return ErrInvalidRequest
	}
	switch value.scopeKind {
	case mutationScopeSource:
		if value.environmentID != "" {
			return ErrInvalidRequest
		}
	case mutationScopeEnvironment:
		if !validUUID(value.environmentID) {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func (value MutationContext) SourceScope() SourceScope { return value.sourceScope }

func (value MutationContext) EnvironmentScope() (Scope, bool) {
	if value.scopeKind != mutationScopeEnvironment || !validUUID(value.environmentID) {
		return Scope{}, false
	}
	return Scope{TenantID: value.sourceScope.TenantID, WorkspaceID: value.sourceScope.WorkspaceID, EnvironmentID: value.environmentID}, true
}

func (value MutationContext) ActorID() string            { return value.actorID }
func (value MutationContext) SubjectID() string          { return value.subjectID }
func (value MutationContext) AuthenticatedAt() time.Time { return value.authenticatedAt }
func (value MutationContext) TraceID() string            { return value.traceID }
func (value MutationContext) IdempotencyKey() string     { return value.idempotencyKey }
func (value MutationContext) RequestHash() string        { return value.requestHash }

type AssetReadConstraint struct {
	initialized  bool
	unrestricted bool
	serviceIDs   []string
}

func NewAssetReadConstraint(unrestricted bool, serviceIDs []string) (AssetReadConstraint, error) {
	ids := slices.Clone(serviceIDs)
	slices.Sort(ids)
	if unrestricted && len(ids) != 0 || len(ids) > 5000 || !validUniqueUUIDs(ids, true) {
		return AssetReadConstraint{}, ErrInvalidRequest
	}
	value := AssetReadConstraint{initialized: true, unrestricted: unrestricted, serviceIDs: ids}
	if err := value.Validate(); err != nil {
		return AssetReadConstraint{}, err
	}
	return value, nil
}

func (value AssetReadConstraint) Validate() error {
	if !value.initialized || value.unrestricted && len(value.serviceIDs) != 0 ||
		len(value.serviceIDs) > 5000 || !slices.IsSorted(value.serviceIDs) || !validUniqueUUIDs(value.serviceIDs, true) {
		return ErrInvalidRequest
	}
	return nil
}

func (value AssetReadConstraint) Unrestricted() bool   { return value.unrestricted }
func (value AssetReadConstraint) ServiceIDs() []string { return slices.Clone(value.serviceIDs) }

type SourceReadConstraint struct {
	initialized    bool
	environmentIDs []string
}

func NewSourceReadConstraint(environmentIDs []string) (SourceReadConstraint, error) {
	ids := slices.Clone(environmentIDs)
	slices.Sort(ids)
	if len(ids) > 100 || !validUniqueUUIDs(ids, true) {
		return SourceReadConstraint{}, ErrInvalidRequest
	}
	value := SourceReadConstraint{initialized: true, environmentIDs: ids}
	if err := value.Validate(); err != nil {
		return SourceReadConstraint{}, err
	}
	return value, nil
}

func (value SourceReadConstraint) Validate() error {
	if !value.initialized || len(value.environmentIDs) > 100 ||
		!slices.IsSorted(value.environmentIDs) || !validUniqueUUIDs(value.environmentIDs, true) {
		return ErrInvalidRequest
	}
	return nil
}

func (value SourceReadConstraint) EnvironmentIDs() []string {
	return slices.Clone(value.environmentIDs)
}

type Reader interface {
	Get(context.Context, AssetLocator) (Asset, error)
}

type ScopeResolver interface {
	ResolveScope(context.Context, string, string) (Scope, error)
}

type SourceScopeResolver interface {
	ResolveSourceScope(context.Context, string) (SourceScope, error)
}

type ConflictScopeResolver interface {
	ResolveConflictScope(context.Context, string, string) (Scope, error)
}

type AssetReadRepository interface {
	GetReadModel(context.Context, AssetLocator, AssetReadConstraint) (AssetDetailReadModel, error)
	List(context.Context, ListAssetsRequest) (AssetPage, error)
}

type Repository interface {
	Reader
	AssetReadRepository
	ScopeResolver
	Create(context.Context, CreateAssetCommand) (AssetMutationResult, error)
	UpdateGovernance(context.Context, UpdateGovernanceCommand) (AssetMutationResult, error)
	Transition(context.Context, TransitionCommand) (AssetMutationResult, error)
}

type MappingRepository interface {
	ConflictScopeResolver
	ListRelationships(context.Context, ListRelationshipsRequest) (RelationshipPage, error)
	ListBindings(context.Context, ListBindingsRequest) (BindingPage, error)
	CreateBinding(context.Context, CreateBindingCommand) (BindingMutationResult, error)
	DeleteBinding(context.Context, DeleteBindingCommand) (MutationReceipt, error)
	ListConflicts(context.Context, ListConflictsRequest) (ConflictPage, error)
	ResolveConflict(context.Context, MappingDecision) (MappingDecisionResult, error)
}

type SourceReadRepository interface {
	SourceScopeResolver
	GetSource(context.Context, SourceLocator, SourceReadConstraint) (SourceReadModel, error)
	ListSources(context.Context, ListSourcesRequest) (SourcePage, error)
	GetSourceRun(context.Context, SourceRunLocator, SourceReadConstraint) (SourceRun, error)
}

type SourceProfileAdmissionResolver interface {
	ResolveProfileAdmission(context.Context, ProfileCode) (BuiltinSourceProfile, error)
}

type SourceProfileRegistry interface {
	Resolve(SourceProfileID) (BuiltinSourceProfile, error)
	ResolveProfileAdmission(context.Context, ProfileCode) (BuiltinSourceProfile, error)
	sourceProfileRegistry()
}

type SourceProfileRegistration struct {
	Selector SourceProfileID
	Profile  BuiltinSourceProfile
}

type immutableSourceProfileRegistry struct {
	bySelector          map[SourceProfileID]BuiltinSourceProfile
	byProfileCode       map[ProfileCode]BuiltinSourceProfile
	initializationError error
}

func (*immutableSourceProfileRegistry) sourceProfileRegistry() {}

func NewSourceProfileRegistry(registrations ...SourceProfileRegistration) (SourceProfileRegistry, error) {
	registry := &immutableSourceProfileRegistry{
		bySelector:    make(map[SourceProfileID]BuiltinSourceProfile, len(registrations)+1),
		byProfileCode: make(map[ProfileCode]BuiltinSourceProfile, len(registrations)+1),
	}
	install := func(registration SourceProfileRegistration) error {
		profile := registration.Profile.Clone()
		if !registration.Selector.Valid() ||
			validateInstalledSourceProfile(profile) != nil ||
			!reservedSourceProfileMatches(registration.Selector, profile) {
			return ErrInvalidRequest
		}
		if _, duplicate := registry.bySelector[registration.Selector]; duplicate {
			return ErrInvalidRequest
		}
		if _, duplicate := registry.byProfileCode[profile.ProfileCode]; duplicate {
			return ErrInvalidRequest
		}
		registry.bySelector[registration.Selector] = profile.Clone()
		registry.byProfileCode[profile.ProfileCode] = profile.Clone()
		return nil
	}
	if err := install(SourceProfileRegistration{
		Selector: SourceProfileIDManualV1,
		Profile:  ManualProfileV1(),
	}); err != nil {
		return nil, ErrInvalidRequest
	}
	for _, registration := range registrations {
		if err := install(registration); err != nil {
			return nil, ErrInvalidRequest
		}
	}
	return registry, nil
}

func reservedSourceProfileMatches(selector SourceProfileID, profile BuiltinSourceProfile) bool {
	switch selector {
	case SourceProfileIDManualV1:
		return sourceProfilesEqual(profile, ManualProfileV1())
	case SourceProfileIDCSVRFC4180V1:
		expected, err := CSVProfileV1(profile.CredentialReferenceID)
		return err == nil && sourceProfilesEqual(profile, expected)
	}
	switch profile.ProfileCode {
	case ProfileCode("MANUAL_V1"):
		return selector == SourceProfileIDManualV1
	case ProfileCode("CSV_RFC4180_V1"):
		return selector == SourceProfileIDCSVRFC4180V1
	}
	return true
}

func sourceProfilesEqual(left, right BuiltinSourceProfile) bool {
	return left.SourceKind == right.SourceKind &&
		left.ProviderKind == right.ProviderKind &&
		left.ProfileCode == right.ProfileCode &&
		left.SyncMode == right.SyncMode &&
		left.FreshnessKind == right.FreshnessKind &&
		left.EnvironmentMapping == right.EnvironmentMapping &&
		left.IntegrationMode == right.IntegrationMode &&
		left.CredentialPurpose == right.CredentialPurpose &&
		left.TrustMode == right.TrustMode &&
		left.NetworkMode == right.NetworkMode &&
		left.ScheduleMode == right.ScheduleMode &&
		left.ParserCode == right.ParserCode &&
		left.CompatibilityClass == right.CompatibilityClass &&
		left.DLPPolicyCode == right.DLPPolicyCode &&
		left.MaxPageItems == right.MaxPageItems &&
		left.MaxPageRelations == right.MaxPageRelations &&
		left.MaxPageBytes == right.MaxPageBytes &&
		left.MaxDocumentBytes == right.MaxDocumentBytes &&
		slices.Equal(left.TrustedPathCodes, right.TrustedPathCodes) &&
		slices.Equal(left.RelationshipTypes, right.RelationshipTypes) &&
		bytes.Equal(left.CanonicalProfileManifest, right.CanonicalProfileManifest) &&
		bytes.Equal(left.CanonicalProviderSchema, right.CanonicalProviderSchema) &&
		left.ProfileManifestSHA256 == right.ProfileManifestSHA256 &&
		left.CanonicalProviderSchemaSHA256 == right.CanonicalProviderSchemaSHA256 &&
		left.IntegrationID == right.IntegrationID &&
		left.CredentialReferenceID == right.CredentialReferenceID &&
		left.TrustReferenceID == right.TrustReferenceID &&
		left.NetworkPolicyReferenceID == right.NetworkPolicyReferenceID &&
		left.RateLimitRequests == right.RateLimitRequests &&
		left.RateLimitWindowSeconds == right.RateLimitWindowSeconds &&
		left.BackpressureBaseSeconds == right.BackpressureBaseSeconds &&
		left.BackpressureMaxSeconds == right.BackpressureMaxSeconds &&
		left.ScheduleExpression == right.ScheduleExpression &&
		left.TypedExtensionCode == right.TypedExtensionCode &&
		left.PreparedExtensionDigest == right.PreparedExtensionDigest
}

func NewBuiltinSourceProfileRegistry() SourceProfileRegistry {
	registry, err := NewSourceProfileRegistry()
	if err != nil {
		return &immutableSourceProfileRegistry{initializationError: ErrInvalidRequest}
	}
	return registry
}

func (registry *immutableSourceProfileRegistry) Resolve(id SourceProfileID) (BuiltinSourceProfile, error) {
	if registry == nil || registry.initializationError != nil {
		return BuiltinSourceProfile{}, ErrInvalidRequest
	}
	if !id.Valid() {
		return BuiltinSourceProfile{}, ErrInvalidRequest
	}
	profile, found := registry.bySelector[id]
	if !found {
		return BuiltinSourceProfile{}, ErrNotFound
	}
	return profile.Clone(), nil
}

func NewBuiltinSourceProfileAdmissionResolver() SourceProfileAdmissionResolver {
	return NewBuiltinSourceProfileRegistry()
}

func (registry *immutableSourceProfileRegistry) ResolveProfileAdmission(_ context.Context, code ProfileCode) (BuiltinSourceProfile, error) {
	if registry == nil || registry.initializationError != nil || !code.Valid() {
		return BuiltinSourceProfile{}, ErrInvalidRequest
	}
	profile, found := registry.byProfileCode[code]
	if !found {
		return BuiltinSourceProfile{}, ErrNotFound
	}
	return profile.Clone(), nil
}

func validUniqueUUIDs(values []string, allowEmpty bool) bool {
	if !allowEmpty && len(values) == 0 {
		return false
	}
	for index, value := range values {
		if !validUUID(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validSafeToken(value string, minimum, maximum int) bool {
	if !validSafeText(value, minimum, maximum) || strings.ContainsAny(value, " \t") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._:/@+-", character) {
			continue
		}
		return false
	}
	return true
}

func validIdempotencyKey(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			index > 0 && strings.ContainsRune("._:/-", character) {
			continue
		}
		return false
	}
	return true
}
