package readexecutor

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"

	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

type victoriaEvidenceRow struct {
	collectedAt time.Time
	canonical   json.RawMessage
}

func parseVictoriaLogsResponse(
	body []byte,
	execution readconnector.ExecutionSpec,
	collectedAt time.Time,
) (readtask.EvidenceCompletion, responseFailure) {
	query, ok := execution.VictoriaLogsSearch()
	windowStart := collectedAt.Add(-execution.Lookback())
	if !ok || execution.Lookback() <= 0 || query.Limit() <= 0 || len(query.Fields()) == 0 ||
		!validExecutionTime(collectedAt) || !validExecutionTime(windowStart) || !windowStart.Before(collectedAt) {
		return readtask.EvidenceCompletion{}, responseRejected
	}
	if len(body) > MaximumUpstreamResponseBytes {
		return readtask.EvidenceCompletion{}, responseRejected
	}
	if len(body) == 0 {
		evidence := readtask.EvidenceCompletion{CollectedAt: collectedAt, Items: make([]json.RawMessage, 0)}
		if execution.ValidateEvidence(evidence) != nil || !evidenceFitsProjectionBudget(evidence) {
			return readtask.EvidenceCompletion{}, responseRejected
		}
		return evidence, responseAccepted
	}

	encodedLines, lineFailure := boundedVictoriaLogLines(body, query.Limit())
	if lineFailure != responseAccepted {
		return readtask.EvidenceCompletion{}, lineFailure
	}
	rows := make([]victoriaEvidenceRow, 0, len(encodedLines))
	for _, encoded := range encodedLines {
		encoded = bytes.TrimSpace(encoded)
		if len(encoded) == 0 {
			return readtask.EvidenceCompletion{}, responseInvalid
		}
		var object map[string]json.RawMessage
		if !strictDecodeJSONObject(encoded, &object) || object == nil {
			return readtask.EvidenceCompletion{}, responseInvalid
		}
		rawTime, found := object["_time"]
		if !found {
			return readtask.EvidenceCompletion{}, responseRejected
		}
		var encodedTime string
		if json.Unmarshal(rawTime, &encodedTime) != nil {
			return readtask.EvidenceCompletion{}, responseRejected
		}
		parsedTime, err := time.Parse(time.RFC3339Nano, encodedTime)
		if err != nil || parsedTime.Location() != time.UTC || parsedTime.Format(time.RFC3339Nano) != encodedTime ||
			parsedTime.Before(windowStart) || !parsedTime.Before(collectedAt) {
			return readtask.EvidenceCompletion{}, responseRejected
		}
		canonical, valid := canonicalJSONObject(encoded)
		if !valid {
			return readtask.EvidenceCompletion{}, responseInvalid
		}
		rows = append(rows, victoriaEvidenceRow{collectedAt: parsedTime, canonical: json.RawMessage(canonical)})
	}
	sort.SliceStable(rows, func(left, right int) bool {
		if !rows[left].collectedAt.Equal(rows[right].collectedAt) {
			return rows[left].collectedAt.Before(rows[right].collectedAt)
		}
		return bytes.Compare(rows[left].canonical, rows[right].canonical) < 0
	})
	items := make([]json.RawMessage, len(rows))
	for index := range rows {
		items[index] = rows[index].canonical
	}
	evidence := readtask.EvidenceCompletion{CollectedAt: collectedAt, Items: items}
	if execution.ValidateEvidence(evidence) != nil || !evidenceFitsProjectionBudget(evidence) {
		return readtask.EvidenceCompletion{}, responseRejected
	}
	return evidence, responseAccepted
}

func boundedVictoriaLogLines(body []byte, maximum int) ([][]byte, responseFailure) {
	if len(body) == 0 || maximum <= 0 {
		return nil, responseRejected
	}
	lines := make([][]byte, 0, min(maximum, 16))
	remaining := body
	for len(remaining) > 0 {
		line := remaining
		if separator := bytes.IndexByte(remaining, '\n'); separator >= 0 {
			line = remaining[:separator]
			remaining = remaining[separator+1:]
		} else {
			remaining = nil
		}
		if len(bytes.TrimSpace(line)) == 0 {
			return nil, responseInvalid
		}
		if len(lines) == maximum {
			return nil, responseRejected
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil, responseRejected
	}
	return lines, responseAccepted
}
