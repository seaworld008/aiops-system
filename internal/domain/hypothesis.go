package domain

type HypothesisStatus string

const (
	HypothesisProposed  HypothesisStatus = "PROPOSED"
	HypothesisConfirmed HypothesisStatus = "CONFIRMED"
	HypothesisRejected  HypothesisStatus = "REJECTED"
)

type Hypothesis struct {
	ID              string
	InvestigationID string
	Status          HypothesisStatus
	Summary         string
}
