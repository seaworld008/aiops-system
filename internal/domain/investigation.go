package domain

import (
	"fmt"
	"time"
)

type InvestigationStatus string

const (
	InvestigationQueued    InvestigationStatus = "QUEUED"
	InvestigationRunning   InvestigationStatus = "RUNNING"
	InvestigationPartial   InvestigationStatus = "PARTIAL"
	InvestigationCompleted InvestigationStatus = "COMPLETED"
	InvestigationFailed    InvestigationStatus = "FAILED"
	InvestigationCancelled InvestigationStatus = "CANCELLED"
)

type ModelStatus string

const (
	ModelPending   ModelStatus = "PENDING"
	ModelRunning   ModelStatus = "RUNNING"
	ModelCompleted ModelStatus = "COMPLETED"
	ModelFailed    ModelStatus = "FAILED"
	ModelSkipped   ModelStatus = "SKIPPED"
	ModelCancelled ModelStatus = "CANCELLED"
)

type Investigation struct {
	ID                 string
	WorkspaceID        string
	IncidentID         string
	Status             InvestigationStatus
	ModelStatus        ModelStatus
	IdempotencyKey     string
	RequestHash        string
	RequestHashVersion string
	PlanBinding        InvestigationPlanBinding
	FailureCode        string
	ModelFailureCode   string
	CreatedAt          time.Time
	StartedAt          time.Time
	CompletedAt        time.Time
	UpdatedAt          time.Time
}

func (investigation Investigation) Validate() error {
	if !validIdentifier(investigation.ID, 256) || !validIdentifier(investigation.WorkspaceID, 256) ||
		!validIdentifier(investigation.IncidentID, 256) {
		return fmt.Errorf("investigation identifiers are invalid")
	}
	switch investigation.Status {
	case InvestigationQueued, InvestigationRunning, InvestigationPartial, InvestigationCompleted,
		InvestigationFailed, InvestigationCancelled:
	default:
		return fmt.Errorf("invalid investigation status %q", investigation.Status)
	}
	switch investigation.ModelStatus {
	case ModelPending, ModelRunning, ModelCompleted, ModelFailed, ModelSkipped, ModelCancelled:
	default:
		return fmt.Errorf("invalid model status %q", investigation.ModelStatus)
	}
	if !validInvestigationModelState(investigation.Status, investigation.ModelStatus) {
		return fmt.Errorf("investigation and model statuses are inconsistent")
	}
	if !ValidIdempotencyKey(investigation.IdempotencyKey) {
		return fmt.Errorf("investigation idempotency key is invalid")
	}
	if !ValidSHA256Hex(investigation.RequestHash) {
		return fmt.Errorf("investigation request hash is invalid")
	}
	switch investigation.RequestHashVersion {
	case InvestigationCreateRequestVersionV1:
		if !investigation.PlanBinding.IsZero() {
			return fmt.Errorf("legacy investigation cannot contain a plan binding")
		}
	case InvestigationCreateRequestVersionV2:
		if err := investigation.PlanBinding.Validate(); err != nil {
			return fmt.Errorf("bound investigation plan is invalid")
		}
	default:
		return fmt.Errorf("investigation request hash version is invalid")
	}
	switch investigation.Status {
	case InvestigationFailed, InvestigationCancelled:
		if !ValidFailureCode(investigation.FailureCode) {
			return fmt.Errorf("failed or cancelled investigation requires a bounded failure code")
		}
	default:
		if investigation.FailureCode != "" {
			return fmt.Errorf("investigation failure code requires FAILED or CANCELLED status")
		}
	}
	if investigation.ModelStatus == ModelFailed {
		if !ValidFailureCode(investigation.ModelFailureCode) {
			return fmt.Errorf("failed model requires a bounded failure code")
		}
	} else if investigation.ModelFailureCode != "" {
		return fmt.Errorf("model failure code requires FAILED model status")
	}
	if investigation.CreatedAt.IsZero() || investigation.UpdatedAt.IsZero() || investigation.UpdatedAt.Before(investigation.CreatedAt) {
		return fmt.Errorf("investigation timestamps are invalid")
	}
	if !timeWithin(investigation.StartedAt, investigation.CreatedAt, investigation.UpdatedAt) ||
		!timeWithin(investigation.CompletedAt, investigation.CreatedAt, investigation.UpdatedAt) ||
		(!investigation.StartedAt.IsZero() && !investigation.CompletedAt.IsZero() && investigation.CompletedAt.Before(investigation.StartedAt)) {
		return fmt.Errorf("investigation lifecycle timestamps are invalid")
	}
	switch investigation.Status {
	case InvestigationQueued:
		if !investigation.StartedAt.IsZero() || !investigation.CompletedAt.IsZero() || investigation.ModelStatus != ModelPending {
			return fmt.Errorf("queued investigation lifecycle is inconsistent")
		}
	case InvestigationRunning:
		if investigation.StartedAt.IsZero() || !investigation.CompletedAt.IsZero() {
			return fmt.Errorf("running investigation lifecycle is inconsistent")
		}
	case InvestigationPartial, InvestigationCompleted:
		if investigation.StartedAt.IsZero() || investigation.CompletedAt.IsZero() ||
			(investigation.ModelStatus != ModelCompleted && investigation.ModelStatus != ModelFailed && investigation.ModelStatus != ModelSkipped) {
			return fmt.Errorf("completed investigation lifecycle is inconsistent")
		}
	case InvestigationFailed:
		if investigation.CompletedAt.IsZero() || investigation.ModelStatus != ModelCancelled {
			return fmt.Errorf("terminal investigation lifecycle is inconsistent")
		}
	case InvestigationCancelled:
		if investigation.CompletedAt.IsZero() || investigation.ModelStatus != ModelCancelled {
			return fmt.Errorf("cancelled investigation lifecycle is inconsistent")
		}
	}
	return nil
}

func validInvestigationModelState(status InvestigationStatus, modelStatus ModelStatus) bool {
	switch status {
	case InvestigationQueued:
		return modelStatus == ModelPending
	case InvestigationRunning:
		return modelStatus == ModelPending || modelStatus == ModelRunning
	case InvestigationCompleted, InvestigationPartial:
		return modelStatus == ModelCompleted || modelStatus == ModelFailed || modelStatus == ModelSkipped
	case InvestigationFailed, InvestigationCancelled:
		return modelStatus == ModelCancelled
	default:
		return false
	}
}

func timeWithin(value, notBefore, notAfter time.Time) bool {
	return value.IsZero() || (!value.Before(notBefore) && !value.After(notAfter))
}
