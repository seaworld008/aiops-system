package assetcatalog

import (
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
}

type builtinSourceProfileRegistry struct{}

func NewBuiltinSourceProfileRegistry() SourceProfileRegistry {
	return builtinSourceProfileRegistry{}
}

func (builtinSourceProfileRegistry) Resolve(id SourceProfileID) (BuiltinSourceProfile, error) {
	if !id.Valid() {
		return BuiltinSourceProfile{}, ErrInvalidRequest
	}
	if id != SourceProfileIDManualV1 {
		return BuiltinSourceProfile{}, ErrNotFound
	}
	return ManualProfileV1().Clone(), nil
}

type builtinSourceProfileAdmissionResolver struct{}

func NewBuiltinSourceProfileAdmissionResolver() SourceProfileAdmissionResolver {
	return builtinSourceProfileAdmissionResolver{}
}

func (builtinSourceProfileAdmissionResolver) ResolveProfileAdmission(_ context.Context, code ProfileCode) (BuiltinSourceProfile, error) {
	if code != ProfileCode("MANUAL_V1") {
		return BuiltinSourceProfile{}, ErrNotFound
	}
	return ManualProfileV1().Clone(), nil
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
