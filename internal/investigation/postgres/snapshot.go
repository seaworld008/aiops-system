package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

// Twenty bounded model hypotheses can legitimately exceed 2 MiB after raw
// proposal bytes are base64 encoded for lossless replay. Eight MiB remains a
// hard database/API bound while covering the maximum accepted hypothesis,
// summary, unknown and evidence-reference envelope with JSON escaping.
const maxSnapshotBytes = 8 * 1024 * 1024

type investigationSnapshotDTO struct {
	ID               string                     `json:"id"`
	WorkspaceID      string                     `json:"workspace_id"`
	IncidentID       string                     `json:"incident_id"`
	Status           domain.InvestigationStatus `json:"status"`
	ModelStatus      domain.ModelStatus         `json:"model_status"`
	IdempotencyKey   string                     `json:"idempotency_key"`
	RequestHash      string                     `json:"request_hash"`
	FailureCode      string                     `json:"failure_code,omitempty"`
	ModelFailureCode string                     `json:"model_failure_code,omitempty"`
	CreatedAt        string                     `json:"created_at"`
	StartedAt        string                     `json:"started_at,omitempty"`
	CompletedAt      string                     `json:"completed_at,omitempty"`
	UpdatedAt        string                     `json:"updated_at"`
}

type hypothesisSnapshotDTO struct {
	ID              string                  `json:"id"`
	WorkspaceID     string                  `json:"workspace_id"`
	IncidentID      string                  `json:"incident_id"`
	InvestigationID string                  `json:"investigation_id"`
	Status          domain.HypothesisStatus `json:"status"`
	Rank            int                     `json:"rank"`
	Confidence      float64                 `json:"confidence"`
	Summary         string                  `json:"summary"`
	ProposalBase64  string                  `json:"proposal_base64"`
	ProposalHash    string                  `json:"proposal_hash"`
	Unknowns        []string                `json:"unknowns"`
	EvidenceIDs     []string                `json:"evidence_ids"`
	CreatedAt       string                  `json:"created_at"`
}

type startModelSnapshotDTO struct {
	Investigation investigationSnapshotDTO `json:"investigation"`
}

type finalizeSnapshotDTO struct {
	Investigation investigationSnapshotDTO `json:"investigation"`
	Hypotheses    []hypothesisSnapshotDTO  `json:"hypotheses"`
}

func encodeStartModelSnapshot(result investigation.StartModelResult) ([]byte, string, error) {
	if err := validateStartModelSnapshot(result); err != nil {
		return nil, "", fmt.Errorf("invalid start-model snapshot")
	}
	return encodeSnapshot(startModelSnapshotDTO{Investigation: investigationToSnapshot(result.Investigation)})
}

func decodeStartModelSnapshot(document []byte) (investigation.StartModelResult, error) {
	var snapshot startModelSnapshotDTO
	if err := decodeSnapshot(document, &snapshot); err != nil {
		return investigation.StartModelResult{}, err
	}
	item, err := investigationFromSnapshot(snapshot.Investigation)
	if err != nil {
		return investigation.StartModelResult{}, err
	}
	result := investigation.StartModelResult{Investigation: item}
	if err := validateStartModelSnapshot(result); err != nil {
		return investigation.StartModelResult{}, err
	}
	return result, nil
}

func encodeFinalizeSnapshot(result investigation.FinalizeInvestigationResult) ([]byte, string, error) {
	if err := validateFinalizeSnapshot(result); err != nil {
		return nil, "", fmt.Errorf("invalid finalize snapshot")
	}
	hypotheses := make([]hypothesisSnapshotDTO, len(result.Hypotheses))
	for index := range result.Hypotheses {
		hypotheses[index] = hypothesisToSnapshot(result.Hypotheses[index])
	}
	return encodeSnapshot(finalizeSnapshotDTO{
		Investigation: investigationToSnapshot(result.Investigation),
		Hypotheses:    hypotheses,
	})
}

func decodeFinalizeSnapshot(document []byte) (investigation.FinalizeInvestigationResult, error) {
	var snapshot finalizeSnapshotDTO
	if err := decodeSnapshot(document, &snapshot); err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	item, err := investigationFromSnapshot(snapshot.Investigation)
	if err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	hypotheses := make([]domain.Hypothesis, len(snapshot.Hypotheses))
	for index := range snapshot.Hypotheses {
		hypotheses[index], err = hypothesisFromSnapshot(snapshot.Hypotheses[index])
		if err != nil {
			return investigation.FinalizeInvestigationResult{}, err
		}
	}
	result := investigation.FinalizeInvestigationResult{Investigation: item, Hypotheses: hypotheses}
	if err := validateFinalizeSnapshot(result); err != nil {
		return investigation.FinalizeInvestigationResult{}, err
	}
	return result, nil
}

func validateStartModelSnapshot(result investigation.StartModelResult) error {
	item := result.Investigation
	if err := item.Validate(); err != nil ||
		!validUUIDs(item.ID, item.WorkspaceID, item.IncidentID) ||
		item.Status != domain.InvestigationRunning || item.ModelStatus != domain.ModelRunning {
		return fmt.Errorf("invalid investigation snapshot")
	}
	return nil
}

func validateFinalizeSnapshot(result investigation.FinalizeInvestigationResult) error {
	item := result.Investigation
	if err := item.Validate(); err != nil || !validUUIDs(item.ID, item.WorkspaceID, item.IncidentID) {
		return fmt.Errorf("invalid investigation snapshot")
	}
	switch item.Status {
	case domain.InvestigationCompleted, domain.InvestigationPartial:
		switch item.ModelStatus {
		case domain.ModelCompleted:
			if len(result.Hypotheses) < 1 || len(result.Hypotheses) > 20 {
				return fmt.Errorf("invalid investigation snapshot")
			}
		case domain.ModelFailed, domain.ModelSkipped:
			if len(result.Hypotheses) != 0 {
				return fmt.Errorf("invalid investigation snapshot")
			}
		default:
			return fmt.Errorf("invalid investigation snapshot")
		}
	case domain.InvestigationCancelled:
		if item.ModelStatus != domain.ModelCancelled || len(result.Hypotheses) != 0 {
			return fmt.Errorf("invalid investigation snapshot")
		}
	default:
		return fmt.Errorf("invalid investigation snapshot")
	}
	seenIDs := make(map[string]struct{}, len(result.Hypotheses))
	previousRank := 0
	for index := range result.Hypotheses {
		hypothesis := result.Hypotheses[index]
		if err := hypothesis.Validate(); err != nil ||
			!validUUIDs(hypothesis.ID, hypothesis.WorkspaceID, hypothesis.IncidentID, hypothesis.InvestigationID) ||
			hypothesis.WorkspaceID != item.WorkspaceID || hypothesis.IncidentID != item.IncidentID ||
			hypothesis.InvestigationID != item.ID || hypothesis.Status != domain.HypothesisProposed ||
			!hypothesis.CreatedAt.Equal(item.CompletedAt) || hypothesis.Unknowns == nil ||
			hypothesis.Rank <= previousRank {
			return fmt.Errorf("invalid investigation snapshot")
		}
		if _, duplicate := seenIDs[hypothesis.ID]; duplicate {
			return fmt.Errorf("invalid investigation snapshot")
		}
		seenIDs[hypothesis.ID] = struct{}{}
		previousRank = hypothesis.Rank
		for _, evidenceID := range hypothesis.EvidenceIDs {
			if !validUUID(evidenceID) {
				return fmt.Errorf("invalid investigation snapshot")
			}
		}
	}
	return nil
}

func encodeSnapshot(value any) ([]byte, string, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return nil, "", fmt.Errorf("encode investigation snapshot")
	}
	document, err = jsoncanonicalizer.Transform(document)
	if err != nil || len(document) < 2 || len(document) > maxSnapshotBytes {
		return nil, "", fmt.Errorf("encode investigation snapshot")
	}
	return document, snapshotSHA256Hex(document), nil
}

func decodeSnapshot(document []byte, destination any) error {
	if len(document) < 2 || len(document) > maxSnapshotBytes {
		return fmt.Errorf("invalid investigation snapshot")
	}
	canonical, err := jsoncanonicalizer.Transform(document)
	if err != nil || !bytes.Equal(canonical, document) {
		return fmt.Errorf("invalid investigation snapshot")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid investigation snapshot")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("invalid investigation snapshot")
	}
	return nil
}

func investigationToSnapshot(item domain.Investigation) investigationSnapshotDTO {
	return investigationSnapshotDTO{
		ID: item.ID, WorkspaceID: item.WorkspaceID, IncidentID: item.IncidentID,
		Status: item.Status, ModelStatus: item.ModelStatus, IdempotencyKey: item.IdempotencyKey,
		RequestHash: item.RequestHash, FailureCode: item.FailureCode, ModelFailureCode: item.ModelFailureCode,
		CreatedAt: snapshotTimeString(item.CreatedAt), StartedAt: snapshotTimeString(item.StartedAt),
		CompletedAt: snapshotTimeString(item.CompletedAt), UpdatedAt: snapshotTimeString(item.UpdatedAt),
	}
}

func investigationFromSnapshot(snapshot investigationSnapshotDTO) (domain.Investigation, error) {
	createdAt, err := parseSnapshotTime(snapshot.CreatedAt, false)
	if err != nil {
		return domain.Investigation{}, err
	}
	startedAt, err := parseSnapshotTime(snapshot.StartedAt, true)
	if err != nil {
		return domain.Investigation{}, err
	}
	completedAt, err := parseSnapshotTime(snapshot.CompletedAt, true)
	if err != nil {
		return domain.Investigation{}, err
	}
	updatedAt, err := parseSnapshotTime(snapshot.UpdatedAt, false)
	if err != nil {
		return domain.Investigation{}, err
	}
	item := domain.Investigation{
		ID: snapshot.ID, WorkspaceID: snapshot.WorkspaceID, IncidentID: snapshot.IncidentID,
		Status: snapshot.Status, ModelStatus: snapshot.ModelStatus, IdempotencyKey: snapshot.IdempotencyKey,
		RequestHash: snapshot.RequestHash, FailureCode: snapshot.FailureCode,
		ModelFailureCode: snapshot.ModelFailureCode, CreatedAt: createdAt, StartedAt: startedAt,
		CompletedAt: completedAt, UpdatedAt: updatedAt,
	}
	if err := item.Validate(); err != nil {
		return domain.Investigation{}, fmt.Errorf("invalid investigation snapshot")
	}
	return item, nil
}

func hypothesisToSnapshot(item domain.Hypothesis) hypothesisSnapshotDTO {
	return hypothesisSnapshotDTO{
		ID: item.ID, WorkspaceID: item.WorkspaceID, IncidentID: item.IncidentID,
		InvestigationID: item.InvestigationID, Status: item.Status, Rank: item.Rank,
		Confidence: item.Confidence, Summary: item.Summary,
		ProposalBase64: base64.StdEncoding.EncodeToString(item.Proposal), ProposalHash: item.ProposalHash,
		Unknowns: append([]string{}, item.Unknowns...), EvidenceIDs: append([]string(nil), item.EvidenceIDs...),
		CreatedAt: snapshotTimeString(item.CreatedAt),
	}
}

func hypothesisFromSnapshot(snapshot hypothesisSnapshotDTO) (domain.Hypothesis, error) {
	proposal, err := base64.StdEncoding.Strict().DecodeString(snapshot.ProposalBase64)
	if err != nil || base64.StdEncoding.EncodeToString(proposal) != snapshot.ProposalBase64 {
		return domain.Hypothesis{}, fmt.Errorf("invalid investigation snapshot")
	}
	createdAt, err := parseSnapshotTime(snapshot.CreatedAt, false)
	if err != nil {
		return domain.Hypothesis{}, err
	}
	item := domain.Hypothesis{
		ID: snapshot.ID, WorkspaceID: snapshot.WorkspaceID, IncidentID: snapshot.IncidentID,
		InvestigationID: snapshot.InvestigationID, Status: snapshot.Status, Rank: snapshot.Rank,
		Confidence: snapshot.Confidence, Summary: snapshot.Summary, Proposal: proposal,
		ProposalHash: snapshot.ProposalHash, Unknowns: append([]string{}, snapshot.Unknowns...),
		EvidenceIDs: append([]string(nil), snapshot.EvidenceIDs...), CreatedAt: createdAt,
	}
	if err := item.Validate(); err != nil {
		return domain.Hypothesis{}, fmt.Errorf("invalid investigation snapshot")
	}
	return item, nil
}

func snapshotTimeString(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func parseSnapshotTime(value string, optional bool) (time.Time, error) {
	if value == "" && optional {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, fmt.Errorf("invalid investigation snapshot")
	}
	return parsed.UTC(), nil
}

func snapshotSHA256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
