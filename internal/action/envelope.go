package action

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	SchemaVersionV1  = "action-envelope.v1"
	SignatureEd25519 = "Ed25519"

	MaxEnvelopeValidity = 30 * time.Minute
	MaxCredentialTTL    = 15 * time.Minute
	MaxAWXHosts         = 10
)

type ActionType string

const (
	ActionKubernetesRolloutRestart ActionType = "K8S_ROLLOUT_RESTART"
	ActionKubernetesScale          ActionType = "K8S_SCALE"
	ActionGitOpsRevert             ActionType = "GITOPS_REVERT"
	ActionAWXServiceRestart        ActionType = "AWX_SERVICE_RESTART"
)

var (
	ErrPlanHashMismatch   = errors.New("action envelope plan hash mismatch")
	ErrInvalidSignature   = errors.New("action envelope signature is invalid")
	ErrEnvelopeExpired    = errors.New("action envelope is expired")
	ErrEnvelopeNotActive  = errors.New("action envelope is not active")
	ErrUnknownSigningKey  = errors.New("unknown action envelope signing key")
	ErrSigningKeyRevoked  = errors.New("action envelope signing key is revoked")
	ErrSigningKeyInactive = errors.New("action envelope signing key is outside its activation window")
)

var (
	tokenPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
	kubernetesPattern  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
	serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$`)
	hex32Pattern       = regexp.MustCompile(`^[a-f0-9]{32}$`)
	hex64Pattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	gitOIDPattern      = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
	repoPathPattern    = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

const maxJCSSafeInteger int64 = 1<<53 - 1

// Envelope is the sole write-side execution input. It deliberately contains
// typed unions rather than arbitrary command, environment, or parameter maps.
type Envelope struct {
	SchemaVersion   string           `json:"schema_version"`
	ActionID        string           `json:"action_id"`
	WorkspaceID     string           `json:"workspace_id"`
	IncidentID      string           `json:"incident_id"`
	RequestedBy     string           `json:"requested_by"`
	ActionType      ActionType       `json:"action_type"`
	Target          TargetRef        `json:"target_ref"`
	Parameters      ActionParameters `json:"parameters"`
	ObservedState   ObservedState    `json:"observed_state"`
	Preconditions   Preconditions    `json:"preconditions"`
	Verification    VerificationPlan `json:"verification"`
	Compensation    CompensationPlan `json:"compensation"`
	Risk            RiskAssessment   `json:"risk"`
	PolicyVersion   string           `json:"policy_version"`
	PlanHash        string           `json:"plan_hash"`
	CredentialScope CredentialScope  `json:"credential_scope"`
	IdempotencyKey  string           `json:"idempotency_key"`
	NotBefore       time.Time        `json:"not_before"`
	ExpiresAt       time.Time        `json:"expires_at"`
	TraceID         string           `json:"trace_id"`
	Signature       Signature        `json:"signature"`
}

type TargetRef struct {
	ServiceID            string                      `json:"service_id"`
	EnvironmentID        string                      `json:"environment_id"`
	KubernetesDeployment *KubernetesDeploymentTarget `json:"kubernetes_deployment,omitempty"`
	GitOpsApplication    *GitOpsTarget               `json:"gitops_application,omitempty"`
	AWXHosts             *AWXTarget                  `json:"awx_hosts,omitempty"`
}

type KubernetesDeploymentTarget struct {
	ClusterID       string `json:"cluster_id"`
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resource_version"`
}

type GitOpsTarget struct {
	RepositoryID string `json:"repository_id"`
	Application  string `json:"application"`
	Path         string `json:"path"`
}

type AWXTarget struct {
	InventoryID               int64   `json:"inventory_id"`
	HostIDs                   []int64 `json:"host_ids"`
	InventorySnapshotSHA256   string  `json:"inventory_snapshot_sha256"`
	JobTemplateSnapshotSHA256 string  `json:"job_template_snapshot_sha256"`
}

type ActionParameters struct {
	KubernetesRolloutRestart *KubernetesRolloutRestartParameters `json:"kubernetes_rollout_restart,omitempty"`
	KubernetesScale          *KubernetesScaleParameters          `json:"kubernetes_scale,omitempty"`
	GitOpsRevert             *GitOpsRevertParameters             `json:"gitops_revert,omitempty"`
	AWXServiceRestart        *AWXServiceRestartParameters        `json:"awx_service_restart,omitempty"`
}

type KubernetesRolloutRestartParameters struct {
	Reason string `json:"reason"`
}

type KubernetesScaleParameters struct {
	Replicas     int32 `json:"replicas"`
	Minimum      int32 `json:"minimum"`
	Maximum      int32 `json:"maximum"`
	HPAAbsent    bool  `json:"hpa_absent"`
	PDBChecked   bool  `json:"pdb_checked"`
	QuotaChecked bool  `json:"quota_checked"`
}

type GitOpsRevertParameters struct {
	Provider     string `json:"provider"`
	BaseCommit   string `json:"base_commit"`
	HeadCommit   string `json:"head_commit"`
	RevertCommit string `json:"revert_commit"`
	DiffSHA256   string `json:"diff_sha256"`
	TreeSHA256   string `json:"tree_sha256"`
}

type AWXServiceRestartParameters struct {
	JobTemplateID int64  `json:"job_template_id"`
	ServiceName   string `json:"service_name"`
	OSFamily      string `json:"os_family"`
	Serial        int32  `json:"serial"`
}

type ObservedState struct {
	KubernetesDeployment *KubernetesDeploymentObservedState `json:"kubernetes_deployment,omitempty"`
	GitOpsApplication    *GitOpsObservedState               `json:"gitops_application,omitempty"`
	AWXService           *AWXServiceObservedState           `json:"awx_service,omitempty"`
}

type KubernetesDeploymentObservedState struct {
	Generation        int64 `json:"generation"`
	Replicas          int32 `json:"replicas"`
	AvailableReplicas int32 `json:"available_replicas"`
	UpdatedReplicas   int32 `json:"updated_replicas"`
}

type GitOpsObservedState struct {
	LiveRevision    string `json:"live_revision"`
	DesiredRevision string `json:"desired_revision"`
	HeadTreeSHA256  string `json:"head_tree_sha256"`
	SyncStatus      string `json:"sync_status"`
	HealthStatus    string `json:"health_status"`
}

type AWXServiceObservedState struct {
	HostCount                  int32  `json:"host_count"`
	ServiceState               string `json:"service_state"`
	InventorySnapshotSHA256    string `json:"inventory_snapshot_sha256"`
	ServiceStateSnapshotSHA256 string `json:"service_state_snapshot_sha256"`
}

type Preconditions struct {
	MappingResult           string `json:"mapping_result"`
	ExpectedResourceVersion string `json:"expected_resource_version"`
	ExpectedGitHeadCommit   string `json:"expected_git_head_commit"`
	RequireWhitelist        bool   `json:"require_whitelist"`
}

type VerificationPlan struct {
	Mode           string `json:"mode"`
	TimeoutSeconds int32  `json:"timeout_seconds"`
}

type CompensationPlan struct {
	Mode    string `json:"mode"`
	Summary string `json:"summary"`
}

type RiskAssessment struct {
	Level       string   `json:"level"`
	ReasonCodes []string `json:"reason_codes"`
}

type CredentialScope struct {
	ConnectorID string `json:"connector_id"`
	Permission  string `json:"permission"`
	Resource    string `json:"resource"`
	TTLSeconds  int32  `json:"ttl_seconds"`
}

type Signature struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

func (envelope Envelope) Validate() error {
	if envelope.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("unsupported schema version %q", envelope.SchemaVersion)
	}
	for name, value := range map[string]string{
		"action id": envelope.ActionID, "workspace id": envelope.WorkspaceID,
		"incident id": envelope.IncidentID, "requester id": envelope.RequestedBy,
		"policy version":  envelope.PolicyVersion,
		"idempotency key": envelope.IdempotencyKey,
	} {
		if !validToken(value) {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if !hex32Pattern.MatchString(envelope.TraceID) {
		return fmt.Errorf("trace id must be 32 lowercase hexadecimal characters")
	}
	if err := validateTimes(envelope.NotBefore, envelope.ExpiresAt); err != nil {
		return err
	}
	if envelope.Preconditions.MappingResult != "EXACT" || !envelope.Preconditions.RequireWhitelist {
		return fmt.Errorf("production action requires exact mapping and whitelist membership")
	}
	if err := envelope.CredentialScope.validate(envelope.ExpiresAt.Sub(envelope.NotBefore)); err != nil {
		return err
	}
	if err := envelope.Verification.validate(); err != nil {
		return err
	}
	if err := envelope.Compensation.validate(); err != nil {
		return err
	}
	if err := envelope.Risk.validate(); err != nil {
		return err
	}
	if envelope.PlanHash != "" && !hex64Pattern.MatchString(envelope.PlanHash) {
		return fmt.Errorf("plan hash must be a lowercase SHA-256 value")
	}
	if err := envelope.Signature.validateOptional(); err != nil {
		return err
	}

	targetCount := countNonNil(
		envelope.Target.KubernetesDeployment != nil,
		envelope.Target.GitOpsApplication != nil,
		envelope.Target.AWXHosts != nil,
	)
	if targetCount != 1 {
		return fmt.Errorf("action envelope must have exactly one target")
	}
	if !validToken(envelope.Target.ServiceID) || !validToken(envelope.Target.EnvironmentID) {
		return fmt.Errorf("target service and environment ids are required")
	}
	parameterCount := countNonNil(
		envelope.Parameters.KubernetesRolloutRestart != nil,
		envelope.Parameters.KubernetesScale != nil,
		envelope.Parameters.GitOpsRevert != nil,
		envelope.Parameters.AWXServiceRestart != nil,
	)
	if parameterCount != 1 {
		return fmt.Errorf("action envelope must have exactly one parameter set")
	}
	observedCount := countNonNil(
		envelope.ObservedState.KubernetesDeployment != nil,
		envelope.ObservedState.GitOpsApplication != nil,
		envelope.ObservedState.AWXService != nil,
	)
	if observedCount != 1 {
		return fmt.Errorf("action envelope must have exactly one observed state")
	}

	switch envelope.ActionType {
	case ActionKubernetesRolloutRestart:
		if envelope.Target.KubernetesDeployment == nil || envelope.Parameters.KubernetesRolloutRestart == nil || envelope.ObservedState.KubernetesDeployment == nil {
			return fmt.Errorf("parameters do not match action type %s", envelope.ActionType)
		}
		return envelope.validateKubernetesRestart()
	case ActionKubernetesScale:
		if envelope.Target.KubernetesDeployment == nil || envelope.Parameters.KubernetesScale == nil || envelope.ObservedState.KubernetesDeployment == nil {
			return fmt.Errorf("parameters do not match action type %s", envelope.ActionType)
		}
		return envelope.validateKubernetesScale()
	case ActionGitOpsRevert:
		if envelope.Target.GitOpsApplication == nil || envelope.Parameters.GitOpsRevert == nil || envelope.ObservedState.GitOpsApplication == nil {
			return fmt.Errorf("parameters do not match action type %s", envelope.ActionType)
		}
		return envelope.validateGitOpsRevert()
	case ActionAWXServiceRestart:
		if envelope.Target.AWXHosts == nil || envelope.Parameters.AWXServiceRestart == nil || envelope.ObservedState.AWXService == nil {
			return fmt.Errorf("parameters do not match action type %s", envelope.ActionType)
		}
		return envelope.validateAWXRestart()
	default:
		return fmt.Errorf("unsupported action type %q", envelope.ActionType)
	}
}

func (envelope Envelope) ValidateAt(now time.Time) error {
	if err := envelope.Validate(); err != nil {
		return err
	}
	if !now.Before(envelope.ExpiresAt) {
		return ErrEnvelopeExpired
	}
	if now.Before(envelope.NotBefore) {
		return ErrEnvelopeNotActive
	}
	return nil
}

func (envelope Envelope) validateKubernetesRestart() error {
	if err := envelope.Target.KubernetesDeployment.validate(); err != nil {
		return err
	}
	parameters := envelope.Parameters.KubernetesRolloutRestart
	if strings.TrimSpace(parameters.Reason) == "" || len(parameters.Reason) > 500 {
		return fmt.Errorf("restart reason is required and limited to 500 bytes")
	}
	if err := envelope.ObservedState.KubernetesDeployment.validate(); err != nil {
		return err
	}
	if envelope.Preconditions.ExpectedResourceVersion != envelope.Target.KubernetesDeployment.ResourceVersion {
		return fmt.Errorf("expected resource version must match the target")
	}
	if envelope.Preconditions.ExpectedGitHeadCommit != "" || envelope.Verification.Mode != "KUBERNETES_ROLLOUT" {
		return fmt.Errorf("invalid Kubernetes restart precondition or verification mode")
	}
	if err := envelope.validateCredentialBinding("PATCH_DEPLOYMENT_RESTART", kubernetesCredentialResource(*envelope.Target.KubernetesDeployment)); err != nil {
		return err
	}
	return nil
}

func (envelope Envelope) validateKubernetesScale() error {
	if err := envelope.Target.KubernetesDeployment.validate(); err != nil {
		return err
	}
	parameters := envelope.Parameters.KubernetesScale
	if parameters.Minimum < 0 || parameters.Maximum < parameters.Minimum || parameters.Replicas < parameters.Minimum || parameters.Replicas > parameters.Maximum {
		return fmt.Errorf("scale replicas must be within the signed minimum and maximum")
	}
	if !parameters.HPAAbsent || !parameters.PDBChecked || !parameters.QuotaChecked {
		return fmt.Errorf("scale requires HPA absence plus PDB and quota checks")
	}
	if err := envelope.ObservedState.KubernetesDeployment.validate(); err != nil {
		return err
	}
	if envelope.Preconditions.ExpectedResourceVersion != envelope.Target.KubernetesDeployment.ResourceVersion || envelope.Verification.Mode != "KUBERNETES_ROLLOUT" {
		return fmt.Errorf("invalid Kubernetes scale precondition or verification mode")
	}
	if err := envelope.validateCredentialBinding("PATCH_DEPLOYMENT_SCALE", kubernetesCredentialResource(*envelope.Target.KubernetesDeployment)); err != nil {
		return err
	}
	return nil
}

func (envelope Envelope) validateGitOpsRevert() error {
	target := envelope.Target.GitOpsApplication
	if !validToken(target.RepositoryID) || !validToken(target.Application) || !validRepositoryPath(target.Path) {
		return fmt.Errorf("invalid GitOps target")
	}
	parameters := envelope.Parameters.GitOpsRevert
	if parameters.Provider != "GITLAB" && parameters.Provider != "GITHUB" {
		return fmt.Errorf("GitOps provider must be GITLAB or GITHUB")
	}
	if !gitOIDPattern.MatchString(parameters.BaseCommit) || !gitOIDPattern.MatchString(parameters.HeadCommit) || !gitOIDPattern.MatchString(parameters.RevertCommit) || !hex64Pattern.MatchString(parameters.DiffSHA256) || !hex64Pattern.MatchString(parameters.TreeSHA256) {
		return fmt.Errorf("GitOps revert requires immutable base, head, revert, diff, and tree bindings")
	}
	state := envelope.ObservedState.GitOpsApplication
	if !gitOIDPattern.MatchString(state.LiveRevision) || !gitOIDPattern.MatchString(state.DesiredRevision) || !hex64Pattern.MatchString(state.HeadTreeSHA256) || !oneOf(state.SyncStatus, "SYNCED", "OUT_OF_SYNC") || !oneOf(state.HealthStatus, "HEALTHY", "DEGRADED", "PROGRESSING", "MISSING", "UNKNOWN") {
		return fmt.Errorf("invalid GitOps observed state")
	}
	if parameters.HeadCommit != state.DesiredRevision || parameters.HeadCommit != envelope.Preconditions.ExpectedGitHeadCommit || envelope.Preconditions.ExpectedResourceVersion != "" {
		return fmt.Errorf("GitOps head revision must match observed and expected state")
	}
	if envelope.Verification.Mode != "ARGO_CD_HEALTH" {
		return fmt.Errorf("GitOps revert requires Argo CD health verification")
	}
	if err := envelope.validateCredentialBinding("CREATE_REVERT_MR", target.RepositoryID); err != nil {
		return err
	}
	return nil
}

func (envelope Envelope) validateAWXRestart() error {
	target := envelope.Target.AWXHosts
	if !safePositiveInteger(target.InventoryID) || len(target.HostIDs) == 0 || len(target.HostIDs) > MaxAWXHosts || !strictlyIncreasingPositive(target.HostIDs) || !hex64Pattern.MatchString(target.InventorySnapshotSHA256) || !hex64Pattern.MatchString(target.JobTemplateSnapshotSHA256) {
		return fmt.Errorf("AWX target requires sorted unique positive host ids")
	}
	parameters := envelope.Parameters.AWXServiceRestart
	if !safePositiveInteger(parameters.JobTemplateID) || !serviceNamePattern.MatchString(parameters.ServiceName) || !oneOf(parameters.OSFamily, "LINUX_SYSTEMD", "WINDOWS_SERVICE") || parameters.Serial != 1 {
		return fmt.Errorf("AWX restart requires a fixed template, typed service, supported OS family, and serial execution")
	}
	state := envelope.ObservedState.AWXService
	if state.HostCount != int32(len(target.HostIDs)) || !oneOf(state.ServiceState, "RUNNING", "STOPPED", "DEGRADED", "UNKNOWN") || state.InventorySnapshotSHA256 != target.InventorySnapshotSHA256 || !hex64Pattern.MatchString(state.ServiceStateSnapshotSHA256) {
		return fmt.Errorf("invalid AWX service observed state")
	}
	if envelope.Preconditions.ExpectedResourceVersion != "" || envelope.Preconditions.ExpectedGitHeadCommit != "" || envelope.Verification.Mode != "AWX_SERVICE_HEALTH" {
		return fmt.Errorf("invalid AWX restart precondition or verification mode")
	}
	resource := fmt.Sprintf("inventory/%d/job-template/%d", target.InventoryID, parameters.JobTemplateID)
	if err := envelope.validateCredentialBinding("LAUNCH_SERVICE_RESTART_TEMPLATE", resource); err != nil {
		return err
	}
	return nil
}

func (target KubernetesDeploymentTarget) validate() error {
	if !validToken(target.ClusterID) || !validToken(target.UID) || !validToken(target.ResourceVersion) {
		return fmt.Errorf("invalid Kubernetes deployment target identity")
	}
	if len(target.Namespace) > 63 || len(target.Name) > 253 || !kubernetesPattern.MatchString(target.Namespace) || !kubernetesPattern.MatchString(target.Name) {
		return fmt.Errorf("invalid Kubernetes deployment target name")
	}
	return nil
}

func (state KubernetesDeploymentObservedState) validate() error {
	if !safePositiveInteger(state.Generation) {
		return fmt.Errorf("Kubernetes generation must be a positive RFC 8785 safe integer")
	}
	if state.Replicas < 0 || state.AvailableReplicas < 0 || state.UpdatedReplicas < 0 || state.AvailableReplicas > state.Replicas || state.UpdatedReplicas > state.Replicas {
		return fmt.Errorf("invalid Kubernetes deployment observed state")
	}
	return nil
}

func (plan VerificationPlan) validate() error {
	if !oneOf(plan.Mode, "KUBERNETES_ROLLOUT", "ARGO_CD_HEALTH", "AWX_SERVICE_HEALTH") || plan.TimeoutSeconds <= 0 || plan.TimeoutSeconds > 900 {
		return fmt.Errorf("invalid verification plan")
	}
	return nil
}

func (plan CompensationPlan) validate() error {
	if !oneOf(plan.Mode, "MANUAL_ONLY", "PROPOSE_ONLY") || strings.TrimSpace(plan.Summary) == "" || len(plan.Summary) > 1000 {
		return fmt.Errorf("invalid compensation plan")
	}
	return nil
}

func (risk RiskAssessment) validate() error {
	if !oneOf(risk.Level, "LOW", "MEDIUM", "HIGH") || len(risk.ReasonCodes) == 0 || len(risk.ReasonCodes) > 16 {
		return fmt.Errorf("invalid risk assessment")
	}
	if !slices.IsSorted(risk.ReasonCodes) {
		return fmt.Errorf("risk reason codes must be sorted")
	}
	for index, reason := range risk.ReasonCodes {
		if !validToken(reason) || (index > 0 && reason == risk.ReasonCodes[index-1]) {
			return fmt.Errorf("invalid or duplicate risk reason code")
		}
	}
	return nil
}

func (scope CredentialScope) validate(validity time.Duration) error {
	if !validToken(scope.ConnectorID) || !validToken(scope.Permission) || !validToken(scope.Resource) {
		return fmt.Errorf("invalid credential scope")
	}
	ttl := time.Duration(scope.TTLSeconds) * time.Second
	if ttl <= 0 || ttl > MaxCredentialTTL || ttl > validity {
		return fmt.Errorf("credential ttl must be positive, at most 15 minutes, and within envelope validity")
	}
	return nil
}

func (signature Signature) validateOptional() error {
	if signature == (Signature{}) {
		return nil
	}
	if signature.Algorithm != SignatureEd25519 || !validToken(signature.KeyID) || signature.Value == "" || len(signature.Value) > 256 {
		return fmt.Errorf("invalid action envelope signature metadata")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(signature.Value)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return fmt.Errorf("invalid action envelope signature encoding")
	}
	return nil
}

func validateTimes(notBefore, expiresAt time.Time) error {
	if notBefore.IsZero() || expiresAt.IsZero() {
		return fmt.Errorf("not_before and expires_at are required")
	}
	_, notBeforeOffset := notBefore.Zone()
	_, expiresAtOffset := expiresAt.Zone()
	if notBeforeOffset != 0 || expiresAtOffset != 0 {
		return fmt.Errorf("action envelope timestamps must use UTC")
	}
	validity := expiresAt.Sub(notBefore)
	if validity <= 0 || validity > MaxEnvelopeValidity {
		return fmt.Errorf("action envelope validity window must be positive and at most 30 minutes")
	}
	return nil
}

func validToken(value string) bool {
	return tokenPattern.MatchString(value)
}

func oneOf(value string, allowed ...string) bool {
	return slices.Contains(allowed, value)
}

func countNonNil(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func strictlyIncreasingPositive(values []int64) bool {
	for index, value := range values {
		if !safePositiveInteger(value) || (index > 0 && value <= values[index-1]) {
			return false
		}
	}
	return true
}

func safePositiveInteger(value int64) bool {
	return value > 0 && value <= maxJCSSafeInteger
}

func validRepositoryPath(value string) bool {
	if value == "" || len(value) > 512 || !repoPathPattern.MatchString(value) || strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "." {
		return false
	}
	segments := strings.Split(value, "/")
	if strings.HasPrefix(segments[0], "-") {
		return false
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || strings.EqualFold(segment, ".git") {
			return false
		}
	}
	return true
}

func kubernetesCredentialResource(target KubernetesDeploymentTarget) string {
	return target.ClusterID + "/" + target.Namespace + "/deployment/" + target.Name
}

func (envelope Envelope) validateCredentialBinding(permission, resource string) error {
	if envelope.CredentialScope.Permission != permission || envelope.CredentialScope.Resource != resource {
		return fmt.Errorf("credential scope does not match action and exact target")
	}
	return nil
}

type Signer interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

type Ed25519Signer struct {
	keyID      string
	privateKey ed25519.PrivateKey
}

func NewEd25519Signer(keyID string, privateKey ed25519.PrivateKey) (*Ed25519Signer, error) {
	if !validToken(keyID) || len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("valid key id and Ed25519 private key are required")
	}
	return &Ed25519Signer{keyID: keyID, privateKey: slices.Clone(privateKey)}, nil
}

func (signer *Ed25519Signer) KeyID() string { return signer.keyID }

func (signer *Ed25519Signer) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ed25519.Sign(signer.privateKey, message), nil
}

type KeyRecord struct {
	PublicKey ed25519.PublicKey
	Revoked   bool
	ActiveAt  time.Time
	RetireAt  time.Time
}

type KeyResolver interface {
	Resolve(context.Context, string) (KeyRecord, error)
}

type StaticKeySet struct {
	records map[string]KeyRecord
}

func NewStaticKeySet(records map[string]KeyRecord) (*StaticKeySet, error) {
	cloned, err := cloneKeyRecords(records)
	if err != nil {
		return nil, err
	}
	return &StaticKeySet{records: cloned}, nil
}

func (keys *StaticKeySet) Resolve(ctx context.Context, keyID string) (KeyRecord, error) {
	if err := ctx.Err(); err != nil {
		return KeyRecord{}, err
	}
	if keys == nil {
		return KeyRecord{}, ErrUnknownSigningKey
	}
	record, exists := keys.records[keyID]
	if !exists {
		return KeyRecord{}, ErrUnknownSigningKey
	}
	record.PublicKey = slices.Clone(record.PublicKey)
	return record, nil
}

type RotatingKeySet struct {
	mu      sync.RWMutex
	records map[string]KeyRecord
}

func NewRotatingKeySet(records map[string]KeyRecord) (*RotatingKeySet, error) {
	cloned, err := cloneKeyRecords(records)
	if err != nil {
		return nil, err
	}
	return &RotatingKeySet{records: cloned}, nil
}

func (keys *RotatingKeySet) Replace(records map[string]KeyRecord) error {
	cloned, err := cloneKeyRecords(records)
	if err != nil {
		return err
	}
	keys.mu.Lock()
	keys.records = cloned
	keys.mu.Unlock()
	return nil
}

func (keys *RotatingKeySet) Resolve(ctx context.Context, keyID string) (KeyRecord, error) {
	if err := ctx.Err(); err != nil {
		return KeyRecord{}, err
	}
	keys.mu.RLock()
	record, exists := keys.records[keyID]
	keys.mu.RUnlock()
	if !exists {
		return KeyRecord{}, ErrUnknownSigningKey
	}
	record.PublicKey = slices.Clone(record.PublicKey)
	return record, nil
}

func cloneKeyRecords(records map[string]KeyRecord) (map[string]KeyRecord, error) {
	cloned := make(map[string]KeyRecord, len(records))
	for keyID, record := range records {
		if !validToken(keyID) || len(record.PublicKey) != ed25519.PublicKeySize || (!record.RetireAt.IsZero() && !record.ActiveAt.IsZero() && !record.ActiveAt.Before(record.RetireAt)) {
			return nil, fmt.Errorf("invalid signing key record")
		}
		record.PublicKey = slices.Clone(record.PublicKey)
		cloned[keyID] = record
	}
	return cloned, nil
}

func Seal(ctx context.Context, envelope Envelope, authenticatedRequester string, signer Signer) (Envelope, error) {
	if signer == nil || !validToken(signer.KeyID()) || !validToken(authenticatedRequester) {
		return Envelope{}, fmt.Errorf("valid action envelope signer is required")
	}
	if envelope.RequestedBy != "" && envelope.RequestedBy != authenticatedRequester {
		return Envelope{}, fmt.Errorf("action requester does not match the authenticated OIDC subject")
	}
	envelope.RequestedBy = authenticatedRequester
	envelope.PlanHash = ""
	envelope.Signature = Signature{}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, err
	}
	planHash, err := calculatePlanHash(envelope)
	if err != nil {
		return Envelope{}, err
	}
	envelope.PlanHash = planHash
	envelope.Signature = Signature{Algorithm: SignatureEd25519, KeyID: signer.KeyID()}
	message, err := canonicalSigningMessage(envelope)
	if err != nil {
		return Envelope{}, err
	}
	signature, err := signer.Sign(ctx, message)
	if err != nil {
		return Envelope{}, fmt.Errorf("sign action envelope: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return Envelope{}, fmt.Errorf("signer returned invalid Ed25519 signature length")
	}
	envelope.Signature.Value = base64.RawURLEncoding.EncodeToString(signature)
	return envelope, nil
}

func Verify(ctx context.Context, envelope Envelope, resolver KeyResolver, now time.Time) error {
	if resolver == nil {
		return fmt.Errorf("action envelope key resolver is required")
	}
	// Validate bounded structure before JCS transformation so an oversized
	// unauthenticated payload cannot force unbounded canonicalization work.
	if err := envelope.Validate(); err != nil {
		return err
	}
	if !now.Before(envelope.ExpiresAt) {
		return ErrEnvelopeExpired
	}
	if now.Before(envelope.NotBefore) {
		return ErrEnvelopeNotActive
	}
	if envelope.PlanHash == "" || envelope.Signature == (Signature{}) {
		return ErrInvalidSignature
	}
	if err := envelope.Signature.validateOptional(); err != nil {
		return err
	}
	expectedHash, err := calculatePlanHash(envelope)
	if err != nil {
		return err
	}
	if !strings.EqualFold(expectedHash, envelope.PlanHash) {
		return ErrPlanHashMismatch
	}
	record, err := resolver.Resolve(ctx, envelope.Signature.KeyID)
	if err != nil {
		return err
	}
	if record.Revoked {
		return ErrSigningKeyRevoked
	}
	if (!record.ActiveAt.IsZero() && now.Before(record.ActiveAt)) || (!record.RetireAt.IsZero() && !now.Before(record.RetireAt)) {
		return ErrSigningKeyInactive
	}
	if len(record.PublicKey) != ed25519.PublicKeySize {
		return ErrUnknownSigningKey
	}
	message, err := canonicalSigningMessage(envelope)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature.Value)
	if err != nil || !ed25519.Verify(record.PublicKey, message, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func calculatePlanHash(envelope Envelope) (string, error) {
	envelope.PlanHash = ""
	envelope.Signature = Signature{}
	canonical, err := canonicalJSON(envelope)
	if err != nil {
		return "", fmt.Errorf("canonicalize action plan: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalSigningMessage(envelope Envelope) ([]byte, error) {
	envelope.Signature.Value = ""
	canonical, err := canonicalJSON(envelope)
	if err != nil {
		return nil, fmt.Errorf("canonicalize action envelope: %w", err)
	}
	return canonical, nil
}

func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(encoded)
}
