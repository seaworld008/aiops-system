package runnerclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/seaworld008/aiops-system/internal/runnergateway"
)

type sensitiveCredentialRequestWire struct {
	SchemaVersion      string                     `json:"schema_version"`
	Phase              string                     `json:"phase"`
	LeaseEpoch         runnergateway.DecimalInt64 `json:"lease_epoch"`
	RevocationID       string                     `json:"revocation_id"`
	ChildCreatePermit  json.RawMessage            `json:"child_create_permit,omitempty"`
	RevokeAccessorB64U json.RawMessage            `json:"revoke_accessor_b64u,omitempty"`
}

func encodeSensitiveCredentialRequest(
	phase string,
	epoch int64,
	revocationID string,
	value []byte,
) ([]byte, error) {
	if epoch <= 0 || !uuidPattern.MatchString(revocationID) || len(value) == 0 {
		return nil, ErrInvalidResponse
	}
	quoted := make([]byte, len(value)+2)
	quoted[0] = '"'
	copy(quoted[1:], value)
	quoted[len(quoted)-1] = '"'
	request := sensitiveCredentialRequestWire{
		SchemaVersion: "runner-credential-anchor-request.v1", Phase: phase,
		LeaseEpoch: runnergateway.DecimalInt64(epoch), RevocationID: revocationID,
	}
	switch phase {
	case "AUTHORIZE_CHILD_CREATE":
		if !bearerPattern.Match(value) {
			clear(quoted)
			return nil, ErrInvalidResponse
		}
		request.ChildCreatePermit = quoted
	case "RECORD_ANCHOR":
		request.RevokeAccessorB64U = quoted
	default:
		clear(quoted)
		return nil, ErrInvalidResponse
	}
	encoded, err := json.Marshal(request)
	clear(quoted)
	if err != nil {
		clear(encoded)
		return nil, ErrInvalidResponse
	}
	return encoded, nil
}

type sensitiveASCII struct{ value []byte }

func (secret *sensitiveASCII) UnmarshalJSON(encoded []byte) error {
	if secret == nil || len(secret.value) != 0 || len(encoded) < 3 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' {
		return ErrInvalidResponse
	}
	value := encoded[1 : len(encoded)-1]
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
			return ErrInvalidResponse
		}
	}
	secret.value = bytes.Clone(value)
	return nil
}

func (*sensitiveASCII) MarshalJSON() ([]byte, error) {
	return nil, errors.New("sensitive Runner wire value cannot be marshaled")
}

func (secret *sensitiveASCII) take() []byte {
	if secret == nil {
		return nil
	}
	value := secret.value
	secret.value = nil
	return value
}

func (secret *sensitiveASCII) clear() {
	if secret == nil {
		return
	}
	clear(secret.value)
	secret.value = nil
}

type jobLeaseWire struct {
	SchemaVersion         string                      `json:"schema_version"`
	Job                   runnergateway.JobDescriptor `json:"job"`
	LeaseToken            sensitiveASCII              `json:"lease_token"`
	LeaseEpoch            runnergateway.DecimalInt64  `json:"lease_epoch"`
	ScopeRevision         runnergateway.DecimalInt64  `json:"scope_revision"`
	LeaseExpiresAt        time.Time                   `json:"lease_expires_at"`
	HeartbeatAfterSeconds int                         `json:"heartbeat_after_seconds"`
}

type credentialPrepareWire struct {
	RevocationID        string         `json:"revocation_id"`
	ChildCreatePermit   sensitiveASCII `json:"child_create_permit"`
	IssuerID            string         `json:"issuer_id"`
	IssuerRevision      string         `json:"issuer_revision"`
	CredentialExpiresAt time.Time      `json:"credential_expires_at"`
}

type jobStartWire struct {
	SchemaVersion     string                     `json:"schema_version"`
	JobID             string                     `json:"job_id"`
	Status            string                     `json:"status"`
	LeaseEpoch        runnergateway.DecimalInt64 `json:"lease_epoch"`
	ScopeRevision     runnergateway.DecimalInt64 `json:"scope_revision"`
	StartedAt         time.Time                  `json:"started_at"`
	CredentialPrepare credentialPrepareWire      `json:"credential_prepare"`
}

type revocationLeaseWire struct {
	SchemaVersion         string                     `json:"schema_version"`
	RevocationID          string                     `json:"revocation_id"`
	ClaimToken            sensitiveASCII             `json:"claim_token"`
	ClaimEpoch            runnergateway.DecimalInt64 `json:"claim_epoch"`
	ClaimExpiresAt        time.Time                  `json:"claim_expires_at"`
	HeartbeatAfterSeconds int                        `json:"heartbeat_after_seconds"`
	TenantID              string                     `json:"tenant_id"`
	WorkspaceID           string                     `json:"workspace_id"`
	EnvironmentID         string                     `json:"environment_id"`
	IssuerID              string                     `json:"issuer_id"`
	IssuerRevision        string                     `json:"issuer_revision"`
	RevokeAccessorB64U    sensitiveASCII             `json:"revoke_accessor_b64u"`
}
