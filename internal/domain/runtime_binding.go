package domain

import (
	"fmt"
	"strings"
	"time"
)

// ConnectorDigestMatchesID verifies the immutable content-addressed READ
// connector identity. The bounded name prefix is followed by exactly one v1
// algorithm marker and the lowercase SHA-256 digest used by RuntimeBinding.
func ConnectorDigestMatchesID(connectorID, connectorDigest string) bool {
	if !ValidConnectorID(connectorID) || !ValidSHA256Hex(connectorDigest) {
		return false
	}
	suffix := "-v1-" + connectorDigest
	if !strings.HasSuffix(connectorID, suffix) {
		return false
	}
	prefixLength := len(connectorID) - len(suffix)
	return prefixLength >= 1 && prefixLength <= 60
}

const (
	InvestigationPlanBindingSchemaVersion = "investigation-plan-manifest.v1"
	ReadTaskRuntimeBindingSchemaVersion   = "read-task-runtime-binding.v1"

	InvestigationCreateRequestVersionV1 = "investigation.create.v1"
	InvestigationCreateRequestVersionV2 = "investigation.create.v2"
)

// InvestigationPlanBinding is the immutable plan identity selected before an
// Investigation is created. It contains digests only and never manifest or
// task content.
type InvestigationPlanBinding struct {
	SchemaVersion  string `json:"schema_version"`
	ManifestDigest string `json:"manifest_digest"`
	RegistryDigest string `json:"registry_digest"`
	ProfileDigest  string `json:"profile_digest"`
	TasksHash      string `json:"tasks_hash"`
}

func (binding InvestigationPlanBinding) Validate() error {
	if binding.SchemaVersion != InvestigationPlanBindingSchemaVersion ||
		!ValidSHA256Hex(binding.ManifestDigest) || !ValidSHA256Hex(binding.RegistryDigest) ||
		!ValidSHA256Hex(binding.ProfileDigest) || !ValidSHA256Hex(binding.TasksHash) {
		return fmt.Errorf("investigation plan binding is invalid")
	}
	return nil
}

func (binding InvestigationPlanBinding) IsZero() bool {
	return binding == (InvestigationPlanBinding{})
}

func (binding InvestigationPlanBinding) Equal(other InvestigationPlanBinding) bool {
	return binding.Validate() == nil && other.Validate() == nil && binding == other
}

// ReadTaskRuntimeBinding is the server-derived immutable execution contract
// selected for one persisted READ task. BoundAt is owned by the repository;
// callers and runtime binders cannot choose it.
type ReadTaskRuntimeBinding struct {
	SchemaVersion   string    `json:"schema_version"`
	ConnectorDigest string    `json:"connector_digest"`
	TargetDigest    string    `json:"target_digest"`
	ExecutorDigest  string    `json:"executor_digest"`
	RuntimeDigest   string    `json:"runtime_digest"`
	BoundAt         time.Time `json:"bound_at"`
}

func (binding ReadTaskRuntimeBinding) Validate() error {
	if binding.SchemaVersion != ReadTaskRuntimeBindingSchemaVersion ||
		!ValidSHA256Hex(binding.ConnectorDigest) || !ValidSHA256Hex(binding.TargetDigest) ||
		!ValidSHA256Hex(binding.ExecutorDigest) || !ValidSHA256Hex(binding.RuntimeDigest) ||
		binding.BoundAt.IsZero() || binding.BoundAt.Location() != time.UTC ||
		!binding.BoundAt.Equal(binding.BoundAt.Truncate(time.Microsecond)) {
		return fmt.Errorf("read task runtime binding is invalid")
	}
	return nil
}

func (binding ReadTaskRuntimeBinding) IsZero() bool {
	return binding == (ReadTaskRuntimeBinding{})
}

func (binding ReadTaskRuntimeBinding) Equal(other ReadTaskRuntimeBinding) bool {
	return binding.Validate() == nil && other.Validate() == nil &&
		binding.SchemaVersion == other.SchemaVersion && binding.ConnectorDigest == other.ConnectorDigest &&
		binding.TargetDigest == other.TargetDigest && binding.ExecutorDigest == other.ExecutorDigest &&
		binding.RuntimeDigest == other.RuntimeDigest && binding.BoundAt.Equal(other.BoundAt)
}
