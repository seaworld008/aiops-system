package assetcatalog

import (
	"maps"
	"slices"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
)

type Kind string

const (
	KindService             Kind = "SERVICE"
	KindLinuxVM             Kind = "LINUX_VM"
	KindWindowsVM           Kind = "WINDOWS_VM"
	KindBareMetalHost       Kind = "BARE_METAL_HOST"
	KindKubernetesCluster   Kind = "KUBERNETES_CLUSTER"
	KindKubernetesNamespace Kind = "KUBERNETES_NAMESPACE"
	KindKubernetesWorkload  Kind = "KUBERNETES_WORKLOAD"
	KindDatabaseInstance    Kind = "DATABASE_INSTANCE"
	KindDatabase            Kind = "DATABASE"
	KindMetricsSource       Kind = "METRICS_SOURCE"
	KindLogSource           Kind = "LOG_SOURCE"
	KindTraceSource         Kind = "TRACE_SOURCE"
	KindAWXInventory        Kind = "AWX_INVENTORY"
	KindArgoApplication     Kind = "ARGO_APPLICATION"
	KindCIPipeline          Kind = "CI_PIPELINE"
	KindGitRepository       Kind = "GIT_REPOSITORY"
	KindCloudResource       Kind = "CLOUD_RESOURCE"
)

func (value Kind) Valid() bool {
	switch value {
	case KindService, KindLinuxVM, KindWindowsVM, KindBareMetalHost,
		KindKubernetesCluster, KindKubernetesNamespace, KindKubernetesWorkload,
		KindDatabaseInstance, KindDatabase, KindMetricsSource, KindLogSource,
		KindTraceSource, KindAWXInventory, KindArgoApplication, KindCIPipeline,
		KindGitRepository, KindCloudResource:
		return true
	}
	return false
}

type SourceKind string

const (
	SourceKindManual             SourceKind = "MANUAL"
	SourceKindCSVImport          SourceKind = "CSV_IMPORT"
	SourceKindControlPlaneAPI    SourceKind = "CONTROL_PLANE_API"
	SourceKindExternalCMDB       SourceKind = "EXTERNAL_CMDB"
	SourceKindVSphere            SourceKind = "VSPHERE"
	SourceKindProxmox            SourceKind = "PROXMOX"
	SourceKindOpenStack          SourceKind = "OPENSTACK"
	SourceKindCloudProvider      SourceKind = "CLOUD_PROVIDER"
	SourceKindKubernetesOperator SourceKind = "KUBERNETES_OPERATOR"
	SourceKindAWXInventory       SourceKind = "AWX_INVENTORY"
)

func (value SourceKind) Valid() bool {
	switch value {
	case SourceKindManual, SourceKindCSVImport, SourceKindControlPlaneAPI,
		SourceKindExternalCMDB, SourceKindVSphere, SourceKindProxmox,
		SourceKindOpenStack, SourceKindCloudProvider, SourceKindKubernetesOperator,
		SourceKindAWXInventory:
		return true
	}
	return false
}

type SourceStatus string

const (
	SourceStatusActive   SourceStatus = "ACTIVE"
	SourceStatusPaused   SourceStatus = "PAUSED"
	SourceStatusDegraded SourceStatus = "DEGRADED"
	SourceStatusDisabled SourceStatus = "DISABLED"
)

func (value SourceStatus) Valid() bool {
	switch value {
	case SourceStatusActive, SourceStatusPaused, SourceStatusDegraded, SourceStatusDisabled:
		return true
	}
	return false
}

type SourceGateStatus string

const (
	SourceGateUnavailable SourceGateStatus = "UNAVAILABLE"
	SourceGateValidating  SourceGateStatus = "VALIDATING"
	SourceGateAvailable   SourceGateStatus = "AVAILABLE"
	SourceGateDegraded    SourceGateStatus = "DEGRADED"
	SourceGateSuspended   SourceGateStatus = "SUSPENDED"
)

func (value SourceGateStatus) Valid() bool {
	switch value {
	case SourceGateUnavailable, SourceGateValidating, SourceGateAvailable,
		SourceGateDegraded, SourceGateSuspended:
		return true
	}
	return false
}

type SourceRevisionStatus string

const (
	SourceRevisionDraft      SourceRevisionStatus = "DRAFT"
	SourceRevisionValidating SourceRevisionStatus = "VALIDATING"
	SourceRevisionValidated  SourceRevisionStatus = "VALIDATED"
	SourceRevisionRejected   SourceRevisionStatus = "REJECTED"
	SourceRevisionPublished  SourceRevisionStatus = "PUBLISHED"
	SourceRevisionSuperseded SourceRevisionStatus = "SUPERSEDED"
)

func (value SourceRevisionStatus) Valid() bool {
	switch value {
	case SourceRevisionDraft, SourceRevisionValidating, SourceRevisionValidated,
		SourceRevisionRejected, SourceRevisionPublished, SourceRevisionSuperseded:
		return true
	}
	return false
}

type SyncMode string

const (
	SyncModeManual    SyncMode = "MANUAL"
	SyncModeOnDemand  SyncMode = "ON_DEMAND"
	SyncModeScheduled SyncMode = "SCHEDULED"
)

func (value SyncMode) Valid() bool {
	switch value {
	case SyncModeManual, SyncModeOnDemand, SyncModeScheduled:
		return true
	}
	return false
}

type RunKind string

const (
	RunKindValidation     RunKind = "VALIDATION"
	RunKindDiscovery      RunKind = "DISCOVERY"
	RunKindCSVImport      RunKind = "CSV_IMPORT"
	RunKindAPIIngestion   RunKind = "API_INGESTION"
	RunKindManualMutation RunKind = "MANUAL_MUTATION"
)

func (value RunKind) Valid() bool {
	switch value {
	case RunKindValidation, RunKindDiscovery, RunKindCSVImport,
		RunKindAPIIngestion, RunKindManualMutation:
		return true
	}
	return false
}

type RunStatus string

const (
	RunStatusQueued     RunStatus = "QUEUED"
	RunStatusDelayed    RunStatus = "DELAYED"
	RunStatusRunning    RunStatus = "RUNNING"
	RunStatusFinalizing RunStatus = "FINALIZING"
	RunStatusSucceeded  RunStatus = "SUCCEEDED"
	RunStatusPartial    RunStatus = "PARTIAL"
	RunStatusFailed     RunStatus = "FAILED"
	RunStatusCancelled  RunStatus = "CANCELLED"
)

func (value RunStatus) Valid() bool {
	switch value {
	case RunStatusQueued, RunStatusDelayed, RunStatusRunning, RunStatusFinalizing,
		RunStatusSucceeded, RunStatusPartial, RunStatusFailed, RunStatusCancelled:
		return true
	}
	return false
}

type RunStage string

const (
	RunStageWaiting     RunStage = "WAITING"
	RunStageDelayed     RunStage = "DELAYED"
	RunStageValidating  RunStage = "VALIDATING"
	RunStageReading     RunStage = "READING"
	RunStageNormalizing RunStage = "NORMALIZING"
	RunStageApplying    RunStage = "APPLYING"
	RunStageCleaningUp  RunStage = "CLEANING_UP"
	RunStageCompleted   RunStage = "COMPLETED"
)

func (value RunStage) Valid() bool {
	switch value {
	case RunStageWaiting, RunStageDelayed, RunStageValidating, RunStageReading,
		RunStageNormalizing, RunStageApplying, RunStageCleaningUp, RunStageCompleted:
		return true
	}
	return false
}

type TriggerType string

const (
	TriggerHuman     TriggerType = "HUMAN"
	TriggerAPI       TriggerType = "API"
	TriggerScheduled TriggerType = "SCHEDULED"
)

func (value TriggerType) Valid() bool {
	switch value {
	case TriggerHuman, TriggerAPI, TriggerScheduled:
		return true
	}
	return false
}

type WorkResultKind string

const (
	WorkResultDataProjection  WorkResultKind = "DATA_PROJECTION"
	WorkResultValidationProof WorkResultKind = "VALIDATION_PROOF"
	WorkResultFailureIntent   WorkResultKind = "FAILURE_INTENT"
)

func (value WorkResultKind) Valid() bool {
	switch value {
	case WorkResultDataProjection, WorkResultValidationProof, WorkResultFailureIntent:
		return true
	}
	return false
}

type WorkResultStatus string

const (
	WorkResultStatusSucceeded WorkResultStatus = "SUCCEEDED"
	WorkResultStatusPartial   WorkResultStatus = "PARTIAL"
	WorkResultStatusFailed    WorkResultStatus = "FAILED"
)

func (value WorkResultStatus) Valid() bool {
	switch value {
	case WorkResultStatusSucceeded, WorkResultStatusPartial, WorkResultStatusFailed:
		return true
	}
	return false
}

type ValidationOutcome string

const (
	ValidationOutcomeSucceeded ValidationOutcome = "SUCCEEDED"
	ValidationOutcomeFailed    ValidationOutcome = "FAILED"
)

func (value ValidationOutcome) Valid() bool {
	switch value {
	case ValidationOutcomeSucceeded, ValidationOutcomeFailed:
		return true
	}
	return false
}

type CredentialCleanupStatus string

const (
	CredentialCleanupNotOpened    CredentialCleanupStatus = "NOT_OPENED"
	CredentialCleanupPending      CredentialCleanupStatus = "PENDING"
	CredentialCleanupRevoked      CredentialCleanupStatus = "REVOKED"
	CredentialCleanupNoCredential CredentialCleanupStatus = "NO_CREDENTIAL"
	CredentialCleanupUncertain    CredentialCleanupStatus = "UNCERTAIN"
)

func (value CredentialCleanupStatus) Valid() bool {
	switch value {
	case CredentialCleanupNotOpened, CredentialCleanupPending, CredentialCleanupRevoked,
		CredentialCleanupNoCredential, CredentialCleanupUncertain:
		return true
	}
	return false
}

type FreshnessKind string

const (
	FreshnessCatalogSequence    FreshnessKind = "CATALOG_SEQUENCE"
	FreshnessObjectSequence     FreshnessKind = "OBJECT_SEQUENCE"
	FreshnessObjectTimeSequence FreshnessKind = "OBJECT_TIME_SEQUENCE"
	FreshnessCheckpointSequence FreshnessKind = "CHECKPOINT_SEQUENCE"
)

func (value FreshnessKind) Valid() bool {
	switch value {
	case FreshnessCatalogSequence, FreshnessObjectSequence,
		FreshnessObjectTimeSequence, FreshnessCheckpointSequence:
		return true
	}
	return false
}

type Lifecycle string

const (
	LifecycleDiscovered  Lifecycle = "DISCOVERED"
	LifecycleActive      Lifecycle = "ACTIVE"
	LifecycleStale       Lifecycle = "STALE"
	LifecycleQuarantined Lifecycle = "QUARANTINED"
	LifecycleRetired     Lifecycle = "RETIRED"
)

func (value Lifecycle) Valid() bool {
	switch value {
	case LifecycleDiscovered, LifecycleActive, LifecycleStale,
		LifecycleQuarantined, LifecycleRetired:
		return true
	}
	return false
}

type Criticality string

const (
	CriticalityLow      Criticality = "LOW"
	CriticalityMedium   Criticality = "MEDIUM"
	CriticalityHigh     Criticality = "HIGH"
	CriticalityCritical Criticality = "CRITICAL"
)

func (value Criticality) Valid() bool {
	switch value {
	case CriticalityLow, CriticalityMedium, CriticalityHigh, CriticalityCritical:
		return true
	}
	return false
}

type DataClassification string

const (
	DataClassificationPublic       DataClassification = "PUBLIC"
	DataClassificationInternal     DataClassification = "INTERNAL"
	DataClassificationConfidential DataClassification = "CONFIDENTIAL"
	DataClassificationRestricted   DataClassification = "RESTRICTED"
)

func (value DataClassification) Valid() bool {
	switch value {
	case DataClassificationPublic, DataClassificationInternal,
		DataClassificationConfidential, DataClassificationRestricted:
		return true
	}
	return false
}

type RelationshipType string

const (
	RelationshipRunsOn            RelationshipType = "RUNS_ON"
	RelationshipContains          RelationshipType = "CONTAINS"
	RelationshipDependsOn         RelationshipType = "DEPENDS_ON"
	RelationshipMonitoredBy       RelationshipType = "MONITORED_BY"
	RelationshipLogsTo            RelationshipType = "LOGS_TO"
	RelationshipTracesTo          RelationshipType = "TRACES_TO"
	RelationshipDeliveredBy       RelationshipType = "DELIVERED_BY"
	RelationshipManagedBy         RelationshipType = "MANAGED_BY"
	RelationshipPrimaryRuntimeFor RelationshipType = "PRIMARY_RUNTIME_FOR"
)

func (value RelationshipType) Valid() bool {
	switch value {
	case RelationshipRunsOn, RelationshipContains, RelationshipDependsOn,
		RelationshipMonitoredBy, RelationshipLogsTo, RelationshipTracesTo,
		RelationshipDeliveredBy, RelationshipManagedBy, RelationshipPrimaryRuntimeFor:
		return true
	}
	return false
}

type RelationshipStatus string

const (
	RelationshipStatusActive   RelationshipStatus = "ACTIVE"
	RelationshipStatusInactive RelationshipStatus = "INACTIVE"
)

func (value RelationshipStatus) Valid() bool {
	switch value {
	case RelationshipStatusActive, RelationshipStatusInactive:
		return true
	}
	return false
}

type BindingRole string

const (
	BindingRolePrimaryRuntime      BindingRole = "PRIMARY_RUNTIME"
	BindingRoleDependency          BindingRole = "DEPENDENCY"
	BindingRoleObservabilitySource BindingRole = "OBSERVABILITY_SOURCE"
	BindingRoleDeliveryTarget      BindingRole = "DELIVERY_TARGET"
	BindingRoleManagedTarget       BindingRole = "MANAGED_TARGET"
)

func (value BindingRole) Valid() bool {
	switch value {
	case BindingRolePrimaryRuntime, BindingRoleDependency, BindingRoleObservabilitySource,
		BindingRoleDeliveryTarget, BindingRoleManagedTarget:
		return true
	}
	return false
}

type BindingStatus string

const (
	BindingStatusActive   BindingStatus = "ACTIVE"
	BindingStatusInactive BindingStatus = "INACTIVE"
)

func (value BindingStatus) Valid() bool {
	switch value {
	case BindingStatusActive, BindingStatusInactive:
		return true
	}
	return false
}

type Provenance string

const (
	ProvenanceManual        Provenance = "MANUAL"
	ProvenanceDiscovered    Provenance = "DISCOVERED"
	ProvenanceMergeDecision Provenance = "MERGE_DECISION"
)

func (value Provenance) Valid() bool {
	switch value {
	case ProvenanceManual, ProvenanceDiscovered, ProvenanceMergeDecision:
		return true
	}
	return false
}

type ConflictStatus string

const (
	ConflictStatusOpen     ConflictStatus = "OPEN"
	ConflictStatusResolved ConflictStatus = "RESOLVED"
	ConflictStatusRejected ConflictStatus = "REJECTED"
)

func (value ConflictStatus) Valid() bool {
	switch value {
	case ConflictStatusOpen, ConflictStatusResolved, ConflictStatusRejected:
		return true
	}
	return false
}

type ConflictResolution string

const (
	ConflictResolutionConfirmExact    ConflictResolution = "CONFIRM_EXACT"
	ConflictResolutionRejectCandidate ConflictResolution = "REJECT_CANDIDATE"
	ConflictResolutionKeepUnresolved  ConflictResolution = "KEEP_UNRESOLVED"
	ConflictResolutionQuarantineAsset ConflictResolution = "QUARANTINE_ASSET"
)

func (value ConflictResolution) Valid() bool {
	switch value {
	case ConflictResolutionConfirmExact, ConflictResolutionRejectCandidate,
		ConflictResolutionKeepUnresolved, ConflictResolutionQuarantineAsset:
		return true
	}
	return false
}

type EnvironmentMappingMode string

const (
	EnvironmentMappingSingle       EnvironmentMappingMode = "SINGLE_ENVIRONMENT"
	EnvironmentMappingExplicitItem EnvironmentMappingMode = "EXPLICIT_ITEM_ENVIRONMENT"
)

func (value EnvironmentMappingMode) Valid() bool {
	switch value {
	case EnvironmentMappingSingle, EnvironmentMappingExplicitItem:
		return true
	}
	return false
}

type FieldOwnership string

const (
	FieldOwnershipSource        FieldOwnership = "SOURCE"
	FieldOwnershipGovernance    FieldOwnership = "GOVERNANCE"
	FieldOwnershipMergeDecision FieldOwnership = "MERGE_DECISION"
)

func (value FieldOwnership) Valid() bool {
	switch value {
	case FieldOwnershipSource, FieldOwnershipGovernance, FieldOwnershipMergeDecision:
		return true
	}
	return false
}

type AssetSort string

const (
	AssetSortDisplayNameAsc   AssetSort = "display_name_asc"
	AssetSortLastObservedDesc AssetSort = "last_observed_at_desc"
)

func (value AssetSort) Valid() bool {
	switch value {
	case AssetSortDisplayNameAsc, AssetSortLastObservedDesc:
		return true
	}
	return false
}

type SourceUsage string

const SourceUsageManualAssetCreate SourceUsage = "manual_asset_create"

func (value SourceUsage) Valid() bool { return value == SourceUsageManualAssetCreate }

type OperationalSummaryStatus string

const OperationalSummaryNotConfigured OperationalSummaryStatus = "NOT_CONFIGURED"

func (value OperationalSummaryStatus) Valid() bool { return value == OperationalSummaryNotConfigured }

type CredentialReferenceID string
type TrustReferenceID string
type NetworkPolicyReferenceID string
type PolicyReferenceID string
type SourceProfileID string
type ProfileCode string
type ExtensionCode string

const SourceProfileIDManualV1 SourceProfileID = "manual-v1"

func (value SourceProfileID) Valid() bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for index, character := range []byte(value) {
		switch {
		case character >= 'a' && character <= 'z':
		case index > 0 && character >= '0' && character <= '9':
		case index > 0 && character == '-' && index+1 < len(value):
			next := value[index+1]
			if (next < 'a' || next > 'z') && (next < '0' || next > '9') {
				return false
			}
		default:
			return false
		}
	}
	return true
}

type Scope struct {
	TenantID, WorkspaceID, EnvironmentID string
}

type SourceScope struct {
	TenantID, WorkspaceID string
}

type AssetLocator struct {
	Scope   Scope
	AssetID string
}

type Asset struct {
	ID, SourceID, ProviderKind, ExternalID, DisplayName string
	Scope                                               Scope
	Kind                                                Kind
	Lifecycle                                           Lifecycle
	MappingStatus                                       domain.MappingStatus
	OwnerGroup                                          *string
	Criticality                                         Criticality
	DataClassification                                  DataClassification
	Labels                                              map[string]string
	LastObservationID, LastObservationChainSHA256       string
	LastObservedAt                                      time.Time
	LastSourceRevision, Version                         int64
	CreatedAt, UpdatedAt                                time.Time
}

func (asset Asset) Clone() Asset {
	asset.Labels = maps.Clone(asset.Labels)
	asset.OwnerGroup = clonePointer(asset.OwnerGroup)
	return asset
}

type Relationship struct {
	ID, SourceID, CanonicalRevisionDigest, LastRunID string
	SourceScope                                      SourceScope
	SourceRevision, LastPageSequence                 int64
	AcceptedCheckpointVersion, RunFenceEpoch         int64
	RelationPageSHA256                               string
	SourceEnvironmentID, TargetEnvironmentID         string
	SourceAssetID, TargetAssetID                     string
	FromExternalID, ToExternalID                     string
	Type                                             RelationshipType
	ProviderPathCode                                 string
	Confidence                                       int
	FreshnessKind                                    FreshnessKind
	FreshnessOrderTime                               *time.Time
	FreshnessOrderSequence                           int64
	ProviderVersionSHA256, RelationFactSHA256        string
	Provenance                                       Provenance
	ProvenanceSourceID                               string
	CrossEnvironmentPolicyReferenceID                PolicyReferenceID
	Status                                           RelationshipStatus
	Version                                          int64
	CreatedAt, UpdatedAt                             time.Time
}

func (relationship Relationship) Clone() Relationship {
	relationship.FreshnessOrderTime = clonePointer(relationship.FreshnessOrderTime)
	return relationship
}

type Conflict struct {
	ID                                            string
	Scope                                         Scope
	AssetID, CandidateAssetID, CandidateServiceID string
	SourceID, ObservationID, Type, FieldName      string
	ExistingValueSHA256, CandidateValueSHA256     string
	Status                                        ConflictStatus
	Resolution                                    ConflictResolution
	ResolutionReasonCode, ResolvedBy              string
	ResolvedAt                                    *time.Time
	Version                                       int64
	CreatedAt, UpdatedAt                          time.Time
}

func (conflict Conflict) Clone() Conflict {
	conflict.ResolvedAt = clonePointer(conflict.ResolvedAt)
	return conflict
}

type ServiceAssetBinding struct {
	ID, ServiceID, AssetID string
	Scope                  Scope
	Role                   BindingRole
	MappingStatus          domain.MappingStatus
	Provenance             Provenance
	ProvenanceSourceID     string
	Status                 BindingStatus
	Version                int64
	CreatedAt, UpdatedAt   time.Time
}

type Source struct {
	ID, TenantID, WorkspaceID, ProviderKind, Name string
	Kind                                          SourceKind
	Status                                        SourceStatus
	PublishedRevision                             int64
	PublishedRevisionDigest                       string
	GateStatus                                    SourceGateStatus
	GateReasonCode                                string
	GateRevision                                  int64
	ValidatedRunID, ValidationDigest              string
	ValidatedBindingDigest                        string
	CheckpointSHA256                              string
	CheckpointVersion, CheckpointSourceRevision   int64
	NextAllowedAt                                 *time.Time
	ConsecutiveFailures                           int
	LastSuccessRunID                              string
	LastSuccessAt                                 *time.Time
	LastCompleteSnapshotRunID                     string
	LastCompleteSnapshotAt                        *time.Time
	Version                                       int64
	CreatedAt, UpdatedAt                          time.Time
}

func (source Source) Clone() Source {
	source.NextAllowedAt = clonePointer(source.NextAllowedAt)
	source.LastSuccessAt = clonePointer(source.LastSuccessAt)
	source.LastCompleteSnapshotAt = clonePointer(source.LastCompleteSnapshotAt)
	return source
}

type SourceRevision struct {
	ID, SourceID, TenantID, WorkspaceID                  string
	Revision                                             int64
	Status                                               SourceRevisionStatus
	CanonicalProfileManifest, CanonicalProviderSchema    []byte
	ProfileManifestSHA256, CanonicalProviderSchemaSHA256 string
	SourceDefinitionDigest, CanonicalRevisionDigest      string
	IntegrationID                                        string
	SyncMode                                             SyncMode
	CredentialReferenceID                                CredentialReferenceID
	TrustReferenceID                                     TrustReferenceID
	NetworkPolicyReferenceID                             NetworkPolicyReferenceID
	AuthorityEnvironmentIDs                              []string
	AuthorityScopeDigest                                 string
	RateLimitRequests, RateLimitWindowSeconds            int64
	BackpressureBaseSeconds, BackpressureMaxSeconds      int64
	ProfileCode                                          ProfileCode
	ScheduleExpression                                   string
	TypedExtensionCode                                   ExtensionCode
	PreparedExtensionDigest                              string
	ValidationRunID, ValidationDigest                    string
	CreatedBy, ChangeReasonCode                          string
	ExpectedSourceVersion, Version                       int64
	CreatedAt, UpdatedAt                                 time.Time
}

func (revision SourceRevision) Clone() SourceRevision {
	revision.CanonicalProfileManifest = slices.Clone(revision.CanonicalProfileManifest)
	revision.CanonicalProviderSchema = slices.Clone(revision.CanonicalProviderSchema)
	revision.AuthorityEnvironmentIDs = slices.Clone(revision.AuthorityEnvironmentIDs)
	return revision
}

type BuiltinSourceProfile struct {
	SourceKind                                           SourceKind
	ProviderKind                                         string
	ProfileCode                                          ProfileCode
	SyncMode                                             SyncMode
	FreshnessKind                                        FreshnessKind
	EnvironmentMapping                                   EnvironmentMappingMode
	IntegrationMode, CredentialPurpose                   string
	TrustMode, NetworkMode, ScheduleMode                 string
	ParserCode, CompatibilityClass, DLPPolicyCode        string
	MaxPageItems, MaxPageRelations                       int64
	MaxPageBytes, MaxDocumentBytes                       int64
	TrustedPathCodes                                     []string
	RelationshipTypes                                    []RelationshipType
	CanonicalProfileManifest, CanonicalProviderSchema    []byte
	ProfileManifestSHA256, CanonicalProviderSchemaSHA256 string
	IntegrationID                                        string
	CredentialReferenceID                                CredentialReferenceID
	TrustReferenceID                                     TrustReferenceID
	NetworkPolicyReferenceID                             NetworkPolicyReferenceID
	RateLimitRequests, RateLimitWindowSeconds            int64
	BackpressureBaseSeconds, BackpressureMaxSeconds      int64
	ScheduleExpression                                   string
	TypedExtensionCode                                   ExtensionCode
	PreparedExtensionDigest                              string
}

func (profile BuiltinSourceProfile) Clone() BuiltinSourceProfile {
	profile.TrustedPathCodes = slices.Clone(profile.TrustedPathCodes)
	profile.RelationshipTypes = slices.Clone(profile.RelationshipTypes)
	profile.CanonicalProfileManifest = slices.Clone(profile.CanonicalProfileManifest)
	profile.CanonicalProviderSchema = slices.Clone(profile.CanonicalProviderSchema)
	return profile
}

type Observation struct {
	ID, SourceID, RunID, ProviderKind, ExternalID   string
	Scope                                           Scope
	SourceRevision                                  int64
	CanonicalRevisionDigest, SourceDefinitionDigest string
	ObservedAt                                      time.Time
	FreshnessKind                                   FreshnessKind
	FreshnessOrderTime                              *time.Time
	FreshnessOrderSequence                          int64
	ProviderVersionSHA256, ProviderFactSHA256       string
	FingerprintSHA256, ProviderProvenanceSHA256     string
	PreviousObservationID, PreviousChainSHA256      string
	ObservationChainSHA256                          string
	AcceptedCheckpointVersion                       int64
	RunFenceEpoch, RunPageSequence                  int64
	SchemaVersion                                   string
	NormalizedDocument, FieldProvenance             []byte
	DocumentSHA256, FieldProvenanceSHA256           string
	Tombstone                                       bool
	TombstoneReasonCode                             string
	CreatedAt                                       time.Time
}

func (observation Observation) Clone() Observation {
	observation.FreshnessOrderTime = clonePointer(observation.FreshnessOrderTime)
	observation.NormalizedDocument = slices.Clone(observation.NormalizedDocument)
	observation.FieldProvenance = slices.Clone(observation.FieldProvenance)
	return observation
}

type SourceRun struct {
	ID, SourceID                          string
	Scope                                 SourceScope
	SourceRevision                        int64
	SourceRevisionDigest                  string
	Kind                                  RunKind
	Status                                RunStatus
	Stage                                 RunStage
	StageChangedAt                        time.Time
	TriggerType                           TriggerType
	GateRevision, PageSequence            int64
	PageDigest                            string
	RelationPageSequence                  int64
	RelationPageDigest                    string
	CursorBeforeSHA256, CursorAfterSHA256 string
	CheckpointVersion                     int64
	NotBefore                             time.Time
	LeaseExpiresAt                        *time.Time
	FenceEpoch, HeartbeatSequence         int64
	FinalPage, CompleteSnapshot           bool
	EffectiveCompleteSnapshot             bool
	WorkResultKind                        WorkResultKind
	WorkResultStatus                      WorkResultStatus
	WorkResultDigest                      string
	WorkResultRecordedAt                  *time.Time
	ValidationOutcome                     ValidationOutcome
	ValidationProofDigest                 string
	CredentialCleanupStatus               CredentialCleanupStatus
	Observed, Created, Changed            int64
	Unchanged, Conflicts                  int64
	Missing, Stale, Restored              int64
	Tombstoned, Rejected                  int64
	FailureCode, TraceID                  string
	Version                               int64
	CreatedAt                             time.Time
	StartedAt, HeartbeatAt, CompletedAt   *time.Time
}

func (run SourceRun) Clone() SourceRun {
	run.LeaseExpiresAt = clonePointer(run.LeaseExpiresAt)
	run.WorkResultRecordedAt = clonePointer(run.WorkResultRecordedAt)
	run.StartedAt = clonePointer(run.StartedAt)
	run.HeartbeatAt = clonePointer(run.HeartbeatAt)
	run.CompletedAt = clonePointer(run.CompletedAt)
	return run
}

type AssetFilter struct {
	Search, ServiceID   string
	Kinds               []Kind
	SourceIDs           []string
	Lifecycles          []Lifecycle
	MappingStatuses     []domain.MappingStatus
	Criticalities       []Criticality
	DataClassifications []DataClassification
}

func (filter AssetFilter) Clone() AssetFilter {
	filter.Kinds = slices.Clone(filter.Kinds)
	filter.SourceIDs = slices.Clone(filter.SourceIDs)
	filter.Lifecycles = slices.Clone(filter.Lifecycles)
	filter.MappingStatuses = slices.Clone(filter.MappingStatuses)
	filter.Criticalities = slices.Clone(filter.Criticalities)
	filter.DataClassifications = slices.Clone(filter.DataClassifications)
	return filter
}

type AssetCursor struct {
	Sort                        AssetSort
	QueryDigest, Value, AssetID string
}

type ListAssetsRequest struct {
	Scope  Scope
	Filter AssetFilter
	Access AssetReadConstraint
	Sort   AssetSort
	Limit  int
	Cursor *AssetCursor
}

func (request ListAssetsRequest) Clone() ListAssetsRequest {
	request.Filter = request.Filter.Clone()
	request.Cursor = clonePointer(request.Cursor)
	return request
}

type CreateAssetCommand struct {
	Context                 MutationContext
	SourceID                string
	Kind                    Kind
	ExternalID, DisplayName string
	OwnerGroup              *string
	Criticality             Criticality
	DataClassification      DataClassification
	Labels                  map[string]string
}

func (command CreateAssetCommand) Clone() CreateAssetCommand {
	command.OwnerGroup = clonePointer(command.OwnerGroup)
	command.Labels = maps.Clone(command.Labels)
	return command
}

type UpdateGovernanceCommand struct {
	Context              MutationContext
	AssetID, DisplayName string
	OwnerGroup           *string
	Criticality          Criticality
	DataClassification   DataClassification
	Labels               map[string]string
	ExpectedVersion      int64
}

func (command UpdateGovernanceCommand) Clone() UpdateGovernanceCommand {
	command.OwnerGroup = clonePointer(command.OwnerGroup)
	command.Labels = maps.Clone(command.Labels)
	return command
}

type TransitionCommand struct {
	Context         MutationContext
	AssetID         string
	To              Lifecycle
	ReasonCode      string
	ExpectedVersion int64
}

type AssetSourceReference struct {
	ID, Name string
	Kind     SourceKind
}

type AssetServiceReference struct {
	ID, Name string
	Role     BindingRole
}

type ConnectionSummary struct{ Status OperationalSummaryStatus }

type CapabilitySummary struct {
	Status OperationalSummaryStatus
	Count  int64
}

type FieldProvenanceSummary struct {
	FieldCode, SourceID, ProviderKind string
	SourceRevision                    int64
	ObservedAt                        time.Time
	ProviderPathCode                  string
	Confidence                        int
	Ownership                         FieldOwnership
}

type AssetRelationCounts struct{ Incoming, Outgoing int64 }

type AssetReadModel struct {
	Asset
	Source     AssetSourceReference
	Services   []AssetServiceReference
	Connection ConnectionSummary
	Capability CapabilitySummary
}

func (model AssetReadModel) Clone() AssetReadModel {
	model.Asset = model.Asset.Clone()
	model.Services = slices.Clone(model.Services)
	return model
}

type AssetDetailReadModel struct {
	AssetReadModel
	FieldProvenance []FieldProvenanceSummary
	Relations       AssetRelationCounts
}

func (model AssetDetailReadModel) Clone() AssetDetailReadModel {
	model.AssetReadModel = model.AssetReadModel.Clone()
	model.FieldProvenance = slices.Clone(model.FieldProvenance)
	return model
}

type AssetPage struct {
	Items                []AssetReadModel
	Next                 *AssetCursor
	ManualCreateEligible bool
}

func (page AssetPage) Clone() AssetPage {
	page.Items = cloneSlice(page.Items, func(value AssetReadModel) AssetReadModel { return value.Clone() })
	page.Next = clonePointer(page.Next)
	return page
}

type RelationshipCursor struct {
	QueryDigest                                  string
	Type                                         RelationshipType
	SourceAssetID, TargetAssetID, RelationshipID string
}

type ListRelationshipsRequest struct {
	Scope             Scope
	Access            AssetReadConstraint
	AssetID, SourceID string
	Types             []RelationshipType
	Statuses          []RelationshipStatus
	Limit             int
	Cursor            *RelationshipCursor
}

func (request ListRelationshipsRequest) Clone() ListRelationshipsRequest {
	request.Types = slices.Clone(request.Types)
	request.Statuses = slices.Clone(request.Statuses)
	request.Cursor = clonePointer(request.Cursor)
	return request
}

type RelationshipPage struct {
	Items []Relationship
	Next  *RelationshipCursor
}

func (page RelationshipPage) Clone() RelationshipPage {
	page.Items = cloneSlice(page.Items, func(value Relationship) Relationship { return value.Clone() })
	page.Next = clonePointer(page.Next)
	return page
}

type BindingCursor struct {
	QueryDigest, ServiceID, AssetID, BindingID string
	Role                                       BindingRole
}

type ListBindingsRequest struct {
	Scope              Scope
	Access             AssetReadConstraint
	ServiceID, AssetID string
	Roles              []BindingRole
	Statuses           []BindingStatus
	Limit              int
	Cursor             *BindingCursor
}

func (request ListBindingsRequest) Clone() ListBindingsRequest {
	request.Roles = slices.Clone(request.Roles)
	request.Statuses = slices.Clone(request.Statuses)
	request.Cursor = clonePointer(request.Cursor)
	return request
}

type BindingPage struct {
	Items []ServiceAssetBinding
	Next  *BindingCursor
}

func (page BindingPage) Clone() BindingPage {
	page.Items = slices.Clone(page.Items)
	page.Next = clonePointer(page.Next)
	return page
}

type CreateBindingCommand struct {
	Context            MutationContext
	ServiceID, AssetID string
	Role               BindingRole
	ReasonCode         string
}

type DeleteBindingCommand struct {
	Context         MutationContext
	BindingID       string
	ReasonCode      string
	ExpectedVersion int64
}

type ConflictObservationReference struct {
	ID, SourceID   string
	SourceRevision int64
	ObservedAt     time.Time
}

type ConflictAssetReference struct {
	ID, DisplayName string
	Kind            Kind
	Lifecycle       Lifecycle
}

type ConflictServiceReference struct{ ID, Name string }

type ConflictImpactCounts struct {
	AssetActiveBindings, AssetActiveRelationships                   int64
	CandidateAssetActiveBindings, CandidateAssetActiveRelationships int64
	CandidateServiceActiveBindings                                  int64
}

type ConflictReadModel struct {
	Conflict
	Observation      ConflictObservationReference
	Asset            ConflictAssetReference
	CandidateAsset   *ConflictAssetReference
	CandidateService *ConflictServiceReference
	Impact           ConflictImpactCounts
}

func (model ConflictReadModel) Clone() ConflictReadModel {
	model.Conflict = model.Conflict.Clone()
	model.CandidateAsset = clonePointer(model.CandidateAsset)
	model.CandidateService = clonePointer(model.CandidateService)
	return model
}

type ConflictCursor struct {
	QueryDigest string
	CreatedAt   time.Time
	ConflictID  string
}

type ListConflictsRequest struct {
	Scope             Scope
	Access            AssetReadConstraint
	AssetID, SourceID string
	Statuses          []ConflictStatus
	Limit             int
	Cursor            *ConflictCursor
}

func (request ListConflictsRequest) Clone() ListConflictsRequest {
	request.Statuses = slices.Clone(request.Statuses)
	request.Cursor = clonePointer(request.Cursor)
	return request
}

type ConflictPage struct {
	Items []ConflictReadModel
	Next  *ConflictCursor
}

func (page ConflictPage) Clone() ConflictPage {
	page.Items = cloneSlice(page.Items, func(value ConflictReadModel) ConflictReadModel { return value.Clone() })
	page.Next = clonePointer(page.Next)
	return page
}

type MappingDecision struct {
	Context         MutationContext
	ConflictID      string
	ServiceID       string
	Resolution      ConflictResolution
	BindingRole     BindingRole
	ReasonCode      string
	ExpectedVersion int64
}

type SourceCursor struct{ QueryDigest, SourceID string }

type ListSourcesRequest struct {
	Scope         SourceScope
	Access        SourceReadConstraint
	Kinds         []SourceKind
	Statuses      []SourceStatus
	GateStatuses  []SourceGateStatus
	Usage         SourceUsage
	EnvironmentID string
	Limit         int
	Cursor        *SourceCursor
}

func (request ListSourcesRequest) Clone() ListSourcesRequest {
	request.Kinds = slices.Clone(request.Kinds)
	request.Statuses = slices.Clone(request.Statuses)
	request.GateStatuses = slices.Clone(request.GateStatuses)
	request.Cursor = clonePointer(request.Cursor)
	return request
}

type SourceReadModel struct {
	Source                        Source
	LatestRevision                SourceRevision
	PublishedRevision             *SourceRevision
	CurrentRun, LastSuccessfulRun *SourceRun
}

func (model SourceReadModel) Clone() SourceReadModel {
	model.Source = model.Source.Clone()
	model.LatestRevision = model.LatestRevision.Clone()
	model.PublishedRevision = cloneWith(model.PublishedRevision, func(value SourceRevision) SourceRevision { return value.Clone() })
	model.CurrentRun = cloneWith(model.CurrentRun, func(value SourceRun) SourceRun { return value.Clone() })
	model.LastSuccessfulRun = cloneWith(model.LastSuccessfulRun, func(value SourceRun) SourceRun { return value.Clone() })
	return model
}

type SourcePage struct {
	Items []SourceReadModel
	Next  *SourceCursor
}

func (page SourcePage) Clone() SourcePage {
	page.Items = cloneSlice(page.Items, func(value SourceReadModel) SourceReadModel { return value.Clone() })
	page.Next = clonePointer(page.Next)
	return page
}

type SourceLocator struct {
	Scope    SourceScope
	SourceID string
}

type SourceRunLocator struct {
	Scope SourceScope
	RunID string
}

type MutationReceipt struct {
	AuditID, TraceID string
	IdempotentReplay bool
}

type AssetMutationResult struct {
	Asset   AssetDetailReadModel
	Receipt MutationReceipt
}

func (result AssetMutationResult) Clone() AssetMutationResult {
	result.Asset = result.Asset.Clone()
	return result
}

type BindingMutationResult struct {
	Binding ServiceAssetBinding
	Receipt MutationReceipt
}

func (result BindingMutationResult) Clone() BindingMutationResult { return result }

type MappingDecisionResult struct {
	Conflict ConflictReadModel
	Binding  *ServiceAssetBinding
	Receipt  MutationReceipt
}

func (result MappingDecisionResult) Clone() MappingDecisionResult {
	result.Conflict = result.Conflict.Clone()
	result.Binding = clonePointer(result.Binding)
	return result
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneWith[T any](value *T, clone func(T) T) *T {
	if value == nil {
		return nil
	}
	result := clone(*value)
	return &result
}

func cloneSlice[T any](values []T, clone func(T) T) []T {
	if values == nil {
		return nil
	}
	result := make([]T, len(values))
	for index, value := range values {
		result[index] = clone(value)
	}
	return result
}
