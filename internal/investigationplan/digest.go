package investigationplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
)

const (
	profileDigestDomain     = "investigation-plan-profile.v1"
	manifestDigestDomain    = ManifestSchemaVersion
	correlationDigestDomain = "investigation-correlation-key.v1"
)

type taskDigestWire struct {
	Key         string          `json:"key"`
	ConnectorID string          `json:"connector_id"`
	Operation   string          `json:"operation"`
	Input       json.RawMessage `json:"input"`
}

type scopeDigestWire struct {
	TenantID      string               `json:"tenant_id"`
	WorkspaceID   string               `json:"workspace_id"`
	EnvironmentID string               `json:"environment_id"`
	ServiceID     string               `json:"service_id"`
	MappingStatus domain.MappingStatus `json:"mapping_status"`
}

func digestProfile(profile compiledProfile) (string, error) {
	tasks := make([]taskDigestWire, len(profile.tasks))
	for index, task := range profile.tasks {
		tasks[index] = taskDigestWire{
			Key: task.Key, ConnectorID: task.ConnectorID, Operation: task.Operation, Input: task.Input,
		}
	}
	return digestJCS(profileDigestDomain, struct {
		RegistryDigest string           `json:"registry_digest"`
		Scope          scopeDigestWire  `json:"scope"`
		Match          MatchDefinition  `json:"match"`
		TasksHash      string           `json:"tasks_hash"`
		Tasks          []taskDigestWire `json:"tasks"`
	}{
		RegistryDigest: profile.registryDigest,
		Scope: scopeDigestWire{
			TenantID: profile.scope.TenantID, WorkspaceID: profile.scope.WorkspaceID,
			EnvironmentID: profile.scope.EnvironmentID, ServiceID: profile.scope.ServiceID,
			MappingStatus: profile.scope.MappingStatus,
		},
		Match: MatchDefinition{
			IntegrationID: profile.integrationID, Provider: profile.provider,
			Labels: append([]LabelMatch(nil), profile.labels...),
		},
		TasksHash: profile.tasksHash, Tasks: tasks,
	})
}

func digestManifest(registryDigest string, profiles []compiledProfile) (string, error) {
	digests := make([]string, len(profiles))
	for index, profile := range profiles {
		digests[index] = profile.profileDigest
	}
	sort.Strings(digests)
	return digestJCS(manifestDigestDomain, struct {
		RegistryDigest string   `json:"registry_digest"`
		ProfileDigests []string `json:"profile_digests"`
	}{RegistryDigest: registryDigest, ProfileDigests: digests})
}

func correlationKey(profile compiledProfile, signal domain.Signal) (string, error) {
	digest, err := digestJCS(correlationDigestDomain, struct {
		TenantID      string `json:"tenant_id"`
		WorkspaceID   string `json:"workspace_id"`
		EnvironmentID string `json:"environment_id"`
		ServiceID     string `json:"service_id"`
		IntegrationID string `json:"integration_id"`
		Provider      string `json:"provider"`
		Fingerprint   string `json:"fingerprint"`
	}{
		TenantID: profile.scope.TenantID, WorkspaceID: profile.scope.WorkspaceID,
		EnvironmentID: profile.scope.EnvironmentID, ServiceID: profile.scope.ServiceID,
		IntegrationID: signal.IntegrationID, Provider: signal.Provider, Fingerprint: signal.Fingerprint,
	})
	if err != nil {
		return "", err
	}
	return "corr.v1." + digest, nil
}

func digestJCS(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil {
		return "", err
	}
	preimage := make([]byte, 0, len(domain)+1+len(canonical))
	preimage = append(preimage, domain...)
	preimage = append(preimage, 0)
	preimage = append(preimage, canonical...)
	digest := sha256.Sum256(preimage)
	return hex.EncodeToString(digest[:]), nil
}
