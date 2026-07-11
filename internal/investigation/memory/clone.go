package memory

import (
	"bytes"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func laterTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}

func cloneSignal(signal domain.Signal) domain.Signal {
	signal.Labels = cloneStringMap(signal.Labels)
	return signal
}

func cloneIncident(incident domain.Incident) domain.Incident {
	return incident
}

func cloneInvestigation(item domain.Investigation) domain.Investigation {
	return item
}

func cloneTask(task domain.ReadTask) domain.ReadTask {
	task.Input = bytes.Clone(task.Input)
	return task
}

func cloneEvidence(evidence domain.Evidence) domain.Evidence {
	evidence.Payload = bytes.Clone(evidence.Payload)
	evidence.Attributes = cloneStringMap(evidence.Attributes)
	return evidence
}

func cloneHypothesis(hypothesis domain.Hypothesis) domain.Hypothesis {
	hypothesis.Proposal = bytes.Clone(hypothesis.Proposal)
	hypothesis.Unknowns = append([]string(nil), hypothesis.Unknowns...)
	hypothesis.EvidenceIDs = append([]string(nil), hypothesis.EvidenceIDs...)
	return hypothesis
}

func cloneHypotheses(hypotheses []domain.Hypothesis) []domain.Hypothesis {
	result := make([]domain.Hypothesis, len(hypotheses))
	for index, hypothesis := range hypotheses {
		result[index] = cloneHypothesis(hypothesis)
	}
	return result
}

func cloneFinalizeResult(result investigation.FinalizeInvestigationResult) investigation.FinalizeInvestigationResult {
	result.Investigation = cloneInvestigation(result.Investigation)
	result.Hypotheses = cloneHypotheses(result.Hypotheses)
	return result
}

func cloneStartModelResult(result investigation.StartModelResult) investigation.StartModelResult {
	result.Investigation = cloneInvestigation(result.Investigation)
	return result
}

func cloneFeedback(feedback domain.Feedback) domain.Feedback {
	feedback.Details = bytes.Clone(feedback.Details)
	return feedback
}

func cloneTasks(tasks []domain.ReadTask) []domain.ReadTask {
	result := make([]domain.ReadTask, len(tasks))
	for index, task := range tasks {
		result[index] = cloneTask(task)
	}
	return result
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
